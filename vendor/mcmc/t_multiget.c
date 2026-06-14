// Regression tests for ASCII multiget / multi-line response parsing in mcmc.
//
// Historically mcmc's parser carried a "broken for ASCII multiget" FIXME: it
// decodes one response line per call and has no memory of being mid-stream, so
// a naive caller that stopped after the first VALUE would leave the remaining
// "VALUE ... \r\n<data>\r\n ... END\r\n" stream in the buffer and later misread
// it as a new command's response.
//
// These tests exercise mcmc_parse_buf_multi(), which keeps GET/STAT read mode
// across lines until END is seen, and the underlying per-line mcmc_parse_buf()
// contract the proxy depends on. Scenarios covered:
//   - multi-key all hit
//   - partial miss (a requested key simply absent from the stream)
//   - value boundaries crossing the read buffer (lines and values split by
//     feeding the stream in tiny chunks)
//   - empty multiget (immediate END) and single-key get
//   - protocol desync detection while mid-multiget
//
// Build & run:  make test   (in vendor/mcmc), or:
//   cc -Wall -Werror -pedantic -o t_multiget t_multiget.c mcmc.c && ./t_multiget

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mcmc.h"

// STATE_DEFAULT is 0 internally in mcmc.c; after a complete stream the parse
// state must return to it. Kept as a named local to avoid a bare magic number.
#define EXPECT_STATE_DEFAULT 0

static int g_fail = 0;

#define MAXKV 16
typedef struct {
    char key[64];
    int klen;
    char val[512]; // holds the value INCLUDING the trailing \r\n
    int vlen;
    uint32_t flags;
} kv_t;

// Simulates a socket read buffer fed from a byte stream in fixed-size chunks.
// A large rbuf with tiny chunks forces both partial response lines (handled via
// MCMC_WANT_READ) and partial values (vlen_read < vlen) to occur, mimicking how
// real recv() boundaries fall in the middle of multiget responses.
typedef struct {
    char rbuf[1024];
    size_t rbufused;
    const char *stream;
    size_t slen;
    size_t spos;
    size_t chunk;
} feeder_t;

static void feeder_init(feeder_t *f, const char *stream, size_t slen, size_t chunk) {
    f->rbufused = 0;
    f->stream = stream;
    f->slen = slen;
    f->spos = 0;
    f->chunk = chunk;
}

static size_t feeder_fill(feeder_t *f) {
    size_t space = sizeof(f->rbuf) - f->rbufused;
    size_t take = f->chunk < space ? f->chunk : space;
    size_t avail = f->slen - f->spos;
    if (take > avail) {
        take = avail;
    }
    if (take > 0) {
        memcpy(f->rbuf + f->rbufused, f->stream + f->spos, take);
        f->rbufused += take;
        f->spos += take;
    }
    return take;
}

static void feeder_consume(feeder_t *f, size_t n) {
    memmove(f->rbuf, f->rbuf + n, f->rbufused - n);
    f->rbufused -= n;
}

// Drive mcmc_parse_buf_multi() over a chunk-fed stream, reassembling any value
// that spans buffer boundaries. Returns:
//   0  clean END terminated stream
//  -1  protocol desync / parse failure (parser refused the stream)
//  -2  stream truncated mid-line or mid-value
//  -3  unexpected (non GET/END) response type
//  -4  more keys than the test buffer holds
static int collect_multiget(const char *stream, size_t slen, size_t chunk,
                            kv_t *out, int *n_out, int *final_state) {
    feeder_t f;
    feeder_init(&f, stream, slen, chunk);
    mcmc_parse_state_t st;
    memset(&st, 0, sizeof(st));
    int n = 0;
    *n_out = 0;
    *final_state = -1;

    while (1) {
        if (f.rbufused == 0) {
            if (f.spos >= f.slen) {
                break; // buffer drained and nothing left to read
            }
            feeder_fill(&f);
        }

        mcmc_resp_t r;
        int s = mcmc_parse_buf_multi(f.rbuf, f.rbufused, &st, &r);

        if (r.code == MCMC_WANT_READ) {
            if (f.spos >= f.slen) {
                *final_state = st.state;
                return -2; // need more data but stream is exhausted
            }
            feeder_fill(&f);
            continue;
        }

        if (s == MCMC_ERR) {
            *final_state = st.state;
            return -1; // desync: parser rejected a line while mid-stream
        }

        if (r.type == MCMC_RESP_END) {
            feeder_consume(&f, r.reslen + r.vlen_read);
            break;
        } else if (r.type == MCMC_RESP_GET) {
            if (n >= MAXKV) {
                return -4;
            }
            kv_t *cur = &out[n];
            cur->klen = (int)r.klen;
            memcpy(cur->key, r.key, r.klen);
            cur->key[r.klen] = '\0';
            cur->flags = r.flags;

            if (r.vlen_read == r.vlen) {
                // whole value already sitting in the buffer
                cur->vlen = (int)r.vlen;
                memcpy(cur->val, r.value, r.vlen);
                feeder_consume(&f, r.reslen + r.vlen_read);
            } else {
                // value crosses the buffer boundary: copy the present prefix,
                // then stream the remainder. The parser must keep GET mode
                // across this so the next line is still parsed as a VALUE/END.
                size_t got = r.vlen_read;
                memcpy(cur->val, r.value, got);
                feeder_consume(&f, r.reslen + r.vlen_read); // buffer now empty
                size_t need = r.vlen - got;
                while (need > 0) {
                    if (f.rbufused == 0) {
                        if (f.spos >= f.slen) {
                            *final_state = st.state;
                            return -2;
                        }
                        feeder_fill(&f);
                    }
                    size_t take = need < f.rbufused ? need : f.rbufused;
                    memcpy(cur->val + got, f.rbuf, take);
                    got += take;
                    need -= take;
                    feeder_consume(&f, take);
                }
                cur->vlen = (int)r.vlen;
            }
            n++;
        } else {
            *final_state = st.state;
            return -3;
        }
    }

    *n_out = n;
    *final_state = st.state;
    return 0;
}

static void check_kv(const kv_t *kv, const char *ekey, uint32_t eflags,
                     const char *eval, const char *tn) {
    size_t evlen = strlen(eval);
    if (kv->klen != (int)strlen(ekey) || memcmp(kv->key, ekey, kv->klen) != 0) {
        printf("  FAIL[%s]: key mismatch: got '%.*s' want '%s'\n",
               tn, kv->klen, kv->key, ekey);
        g_fail++;
        return;
    }
    if (kv->flags != eflags) {
        printf("  FAIL[%s]: flags mismatch for '%s': got %u want %u\n",
               tn, ekey, kv->flags, eflags);
        g_fail++;
        return;
    }
    if (kv->vlen != (int)(evlen + 2)) {
        printf("  FAIL[%s]: vlen mismatch for '%s': got %d want %d\n",
               tn, ekey, kv->vlen, (int)(evlen + 2));
        g_fail++;
        return;
    }
    if (memcmp(kv->val, eval, evlen) != 0 ||
        kv->val[evlen] != '\r' || kv->val[evlen + 1] != '\n') {
        printf("  FAIL[%s]: value mismatch for '%s': got '%.*s'\n",
               tn, ekey, (int)evlen, kv->val);
        g_fail++;
        return;
    }
}

// Multi-key hit + value-boundary-crossing, replayed at several chunk sizes.
// The 18-byte "gamma" value and the response lines themselves are split apart
// at the smaller chunk sizes, so this single buffer covers both "multi key hit"
// and "value crosses buffer".
static void test_multi_hit(void) {
    const char *stream =
        "VALUE alpha 0 5\r\nworld\r\n"
        "VALUE be 1 3\r\nxyz\r\n"
        "VALUE gamma 12 18\r\nboundary-crosser!!\r\n"
        "END\r\n";
    size_t slen = strlen(stream);
    size_t chunks[] = {1024, 8, 3, 1};

    printf("test_multi_hit (multi-key hit + value crosses buffer):\n");
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        kv_t kv[MAXKV];
        int n = 0, fs = -1;
        int rc = collect_multiget(stream, slen, chunks[i], kv, &n, &fs);
        char tn[64];
        snprintf(tn, sizeof(tn), "chunk=%zu", chunks[i]);
        if (rc != 0) {
            printf("  FAIL[%s]: collect rc=%d (expected 0)\n", tn, rc);
            g_fail++;
            continue;
        }
        if (n != 3) {
            printf("  FAIL[%s]: got %d values (expected 3)\n", tn, n);
            g_fail++;
            continue;
        }
        if (fs != EXPECT_STATE_DEFAULT) {
            printf("  FAIL[%s]: parse state not reset after END (got %d)\n", tn, fs);
            g_fail++;
        }
        check_kv(&kv[0], "alpha", 0, "world", tn);
        check_kv(&kv[1], "be", 1, "xyz", tn);
        check_kv(&kv[2], "gamma", 12, "boundary-crosser!!", tn);
    }
}

// A requested key that misses simply never appears in the stream; the hits on
// either side must still be parsed and END must still terminate cleanly.
static void test_partial_miss(void) {
    // requested: k1 k2 k3 ; k2 missed.
    const char *stream =
        "VALUE k1 0 2\r\nAA\r\n"
        "VALUE k3 0 2\r\nCC\r\n"
        "END\r\n";
    size_t slen = strlen(stream);
    size_t chunks[] = {1024, 4, 1};

    printf("test_partial_miss:\n");
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        kv_t kv[MAXKV];
        int n = 0, fs = -1;
        int rc = collect_multiget(stream, slen, chunks[i], kv, &n, &fs);
        char tn[64];
        snprintf(tn, sizeof(tn), "chunk=%zu", chunks[i]);
        if (rc != 0 || n != 2) {
            printf("  FAIL[%s]: rc=%d n=%d (expected rc=0 n=2)\n", tn, rc, n);
            g_fail++;
            continue;
        }
        check_kv(&kv[0], "k1", 0, "AA", tn);
        check_kv(&kv[1], "k3", 0, "CC", tn);
    }
}

// An all-miss multiget is just "END\r\n": zero values, clean termination.
static void test_all_miss(void) {
    const char *stream = "END\r\n";
    size_t slen = strlen(stream);
    size_t chunks[] = {1024, 1};

    printf("test_all_miss (immediate END):\n");
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        kv_t kv[MAXKV];
        int n = -1, fs = -1;
        int rc = collect_multiget(stream, slen, chunks[i], kv, &n, &fs);
        char tn[64];
        snprintf(tn, sizeof(tn), "chunk=%zu", chunks[i]);
        if (rc != 0 || n != 0 || fs != EXPECT_STATE_DEFAULT) {
            printf("  FAIL[%s]: rc=%d n=%d state=%d (expected 0/0/default)\n",
                   tn, rc, n, fs);
            g_fail++;
        }
    }
}

// Single hit followed by END behaves like a 1-element multiget.
static void test_single_key(void) {
    const char *stream = "VALUE solo 0 4\r\ndata\r\nEND\r\n";
    size_t slen = strlen(stream);
    size_t chunks[] = {1024, 1};

    printf("test_single_key:\n");
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        kv_t kv[MAXKV];
        int n = 0, fs = -1;
        int rc = collect_multiget(stream, slen, chunks[i], kv, &n, &fs);
        char tn[64];
        snprintf(tn, sizeof(tn), "chunk=%zu", chunks[i]);
        if (rc != 0 || n != 1) {
            printf("  FAIL[%s]: rc=%d n=%d (expected rc=0 n=1)\n", tn, rc, n);
            g_fail++;
            continue;
        }
        check_kv(&kv[0], "solo", 0, "data", tn);
    }
}

// While mid-multiget the only valid lines are VALUE or END. Anything else means
// the stream is desynced; the stateful parser must flag it instead of silently
// returning a bogus response (which is the failure the old FIXME warned about).
static void test_desync_detected(void) {
    const char *stream =
        "VALUE foo 0 3\r\nbar\r\n"
        "STORED\r\n"; // illegal inside a multiget value stream
    size_t slen = strlen(stream);

    printf("test_desync_detected:\n");
    kv_t kv[MAXKV];
    int n = 0, fs = -1;
    int rc = collect_multiget(stream, slen, 1024, kv, &n, &fs);
    if (rc != -1) {
        printf("  FAIL: expected desync (rc=-1), got rc=%d\n", rc);
        g_fail++;
    }
    if (fs != EXPECT_STATE_DEFAULT) {
        printf("  FAIL: parse state not reset after desync (got %d)\n", fs);
        g_fail++;
    }
}

// Locks in the per-line contract that the proxy relies on: the stateless
// mcmc_parse_buf(), driven directly in a loop and advanced by
// (reslen + vlen_read), yields each VALUE then END for a fully-buffered
// multiget. Regressions here would break proxy_network.c.
static void test_raw_perline_contract(void) {
    const char *stream =
        "VALUE one 0 3\r\naaa\r\n"
        "VALUE two 0 3\r\nbbb\r\n"
        "END\r\n";
    size_t total = strlen(stream);
    size_t off = 0;
    int got = 0;
    int saw_end = 0;

    printf("test_raw_perline_contract:\n");
    while (off < total) {
        mcmc_resp_t r;
        int s = mcmc_parse_buf(stream + off, total - off, &r);
        if (r.code == MCMC_WANT_READ) {
            printf("  FAIL: unexpected WANT_READ on fully-buffered input\n");
            g_fail++;
            break;
        }
        if (s == MCMC_ERR) {
            printf("  FAIL: parse error code=%d\n", r.code);
            g_fail++;
            break;
        }
        if (r.type == MCMC_RESP_GET) {
            got++;
            off += r.reslen + r.vlen_read;
        } else if (r.type == MCMC_RESP_END) {
            saw_end = 1;
            break;
        } else {
            printf("  FAIL: unexpected type %d\n", r.type);
            g_fail++;
            break;
        }
    }
    if (got != 2 || !saw_end) {
        printf("  FAIL: got %d values, saw_end=%d (expected 2/1)\n", got, saw_end);
        g_fail++;
    }
}

int main(void) {
    test_multi_hit();
    test_partial_miss();
    test_all_miss();
    test_single_key();
    test_desync_detected();
    test_raw_perline_contract();

    if (g_fail == 0) {
        printf("\nALL MULTIGET TESTS PASSED\n");
        return 0;
    }
    printf("\n%d MULTIGET TEST CHECK(S) FAILED\n", g_fail);
    return 1;
}
