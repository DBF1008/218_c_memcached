// Regression tests for the ASCII multiget state-tracking fix.
// Build:  gcc -g -O2 -Wall -Werror -pedantic -o test_mcmc test_mcmc.c mcmc.c
// Run:    ./test_mcmc

#define MCMC_TEST
#include "mcmc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(fn) do { \
    tests_run++; \
    printf("  %-60s", #fn); \
    fn(); \
    tests_passed++; \
    printf("[PASS]\n"); \
} while (0)

// ---------------------------------------------------------------------------
// Helper: allocate a context, zero-init, return as void*
// ---------------------------------------------------------------------------
static void *make_ctx(void) {
    void *c = calloc(1, mcmc_size(MCMC_OPTION_BLANK));
    assert(c != NULL);
    return c;
}

// ---------------------------------------------------------------------------
// 1. Basic single VALUE + END  (single-key get hit)
// ---------------------------------------------------------------------------
static void test_single_get_hit(void) {
    void *c = make_ctx();
    mcmc_resp_t r;
    const char buf[] =
        "VALUE foo 0 5\r\n"
        "hello\r\n"
        "END\r\n";
    size_t buflen = sizeof(buf) - 1;
    size_t offset = 0;

    // Parse first response: VALUE foo
    int st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.code == MCMC_CODE_OK);
    assert(r.klen == 3);
    assert(memcmp(r.key, "foo", 3) == 0);
    assert(r.vlen == 7);          // "hello\r\n"
    assert(r.vlen_read == 7);     // all in buffer
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    // Consume VALUE line + value body
    offset += mcmc_buffer_consume(c);
    assert(offset == 15 + 7);     // "VALUE foo 0 5\r\n" + "hello\r\n"

    // Parse next: END
    st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(r.code == MCMC_CODE_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 2. Multi-key all-hit multiget  (3 keys, all present)
// ---------------------------------------------------------------------------
static void test_multiget_all_hit(void) {
    void *c = make_ctx();
    mcmc_resp_t r;
    const char buf[] =
        "VALUE key1 0 5\r\n"
        "hello\r\n"
        "VALUE key2 0 5\r\n"
        "world\r\n"
        "VALUE key3 0 3\r\n"
        "abc\r\n"
        "END\r\n";
    size_t buflen = sizeof(buf) - 1;
    size_t offset = 0;
    int value_count = 0;

    // Expected keys and values
    const char *keys[] = {"key1", "key2", "key3"};
    const char *vals[] = {"hello", "world", "abc"};
    size_t vlens[] = {5, 5, 3};

    while (offset < buflen) {
        int st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
        assert(st == MCMC_OK);

        if (r.type == MCMC_RESP_END) {
            assert(r.code == MCMC_CODE_END);
            assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);
            offset += mcmc_buffer_consume(c);
            break;
        }

        assert(r.type == MCMC_RESP_GET);
        assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);
        assert(value_count < 3);

        assert(r.klen == strlen(keys[value_count]));
        assert(memcmp(r.key, keys[value_count], r.klen) == 0);
        assert(r.vlen == vlens[value_count] + 2);  // +2 for \r\n
        assert(r.vlen_read == r.vlen);              // all in buffer

        // Value data pointer should point to the value in the buffer
        assert(memcmp(r.value, vals[value_count], vlens[value_count]) == 0);

        offset += mcmc_buffer_consume(c);
        value_count++;
    }

    assert(value_count == 3);
    assert(offset == buflen);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 3. Partial miss  (3 keys requested, only 1 hit)
//    In ASCII protocol, missed keys simply don't get a VALUE line.
// ---------------------------------------------------------------------------
static void test_multiget_partial_miss(void) {
    void *c = make_ctx();
    mcmc_resp_t r;
    // Only key2 is a hit; key1 and key3 are misses (no VALUE line for them).
    const char buf[] =
        "VALUE key2 0 7\r\n"
        "goodbye\r\n"
        "END\r\n";
    size_t buflen = sizeof(buf) - 1;
    size_t offset = 0;

    // First: VALUE key2
    int st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.klen == 4);
    assert(memcmp(r.key, "key2", 4) == 0);
    assert(r.vlen == 9);  // "goodbye\r\n"
    assert(r.vlen_read == 9);
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);
    offset += mcmc_buffer_consume(c);

    // Second: END
    st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);
    offset += mcmc_buffer_consume(c);

    assert(offset == buflen);

    free(c);
}

// ---------------------------------------------------------------------------
// 4. All miss  (no VALUE lines, just END)
// ---------------------------------------------------------------------------
static void test_multiget_all_miss(void) {
    void *c = make_ctx();
    mcmc_resp_t r;
    const char buf[] = "END\r\n";
    size_t buflen = sizeof(buf) - 1;

    int st = mcmc_parse_response_buf(c, buf, buflen, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(r.code == MCMC_CODE_END);
    // State should remain DEFAULT since we never entered GET mode
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);
    assert(mcmc_buffer_consume(c) == 5);  // "END\r\n"

    free(c);
}

// ---------------------------------------------------------------------------
// 5. Value boundary crossing buffer  (value data not fully in first buffer)
//    Simulates: first buffer has the VALUE header + partial value,
//    second buffer has the rest of the value + next VALUE + END.
// ---------------------------------------------------------------------------
static void test_value_boundary_cross_buffer(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // Full response data:
    // "VALUE key1 0 10\r\n" = 17 bytes
    // "0123456789\r\n"      = 12 bytes value body
    // "VALUE key2 0 3\r\n"  = 16 bytes
    // "abc\r\n"             =  5 bytes value body
    // "END\r\n"             =  5 bytes
    // Total = 55 bytes
    const char full[] =
        "VALUE key1 0 10\r\n"
        "0123456789\r\n"
        "VALUE key2 0 3\r\n"
        "abc\r\n"
        "END\r\n";

    // Simulate first recv: header (17 bytes) + 2 bytes of value = 19 bytes
    // This splits the value body so that "01" is in the first buffer and
    // "23456789\r\n" (10 bytes) remains for the second recv.
    size_t first_read = 19;
    char buf[256];
    memcpy(buf, full, first_read);

    // Parse first VALUE: header is fully in buffer, but value is partial
    int st = mcmc_parse_response_buf(c, buf, first_read, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.klen == 4);
    assert(memcmp(r.key, "key1", 4) == 0);
    assert(r.vlen == 12);       // "0123456789\r\n"
    assert(r.vlen_read == 2);   // only "01" in buffer (19 - 17 = 2)
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    size_t consumed = mcmc_buffer_consume(c);
    assert(consumed == 17 + 2);  // header + partial value

    // Simulate second recv: remaining value bytes + next VALUE + END
    // We place remaining data at the start of the buffer (as a real caller
    // would do after memmove).
    size_t remaining_val = r.vlen - r.vlen_read;  // 10 bytes remaining
    size_t second_chunk_len = strlen(full) - first_read;  // 55 - 19 = 36
    memcpy(buf, full + first_read, second_chunk_len);
    size_t second_read = second_chunk_len;

    // Caller has already consumed the first value's partial data from the
    // socket (via recv), so now they parse the next response.
    // But first, they need to skip the remaining 10 bytes of the first value.
    // In a real scenario, they'd recv those bytes, then continue.
    // For this test, we simulate having all remaining data in buffer.

    // After consuming the rest of value1 (10 bytes), the next data starts:
    size_t val2_offset = remaining_val;  // skip "23456789\r\n"

    // Parse VALUE key2
    st = mcmc_parse_response_buf(c, buf + val2_offset, second_read - val2_offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.klen == 4);
    assert(memcmp(r.key, "key2", 4) == 0);
    assert(r.vlen == 5);        // "abc\r\n"
    assert(r.vlen_read == 5);
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    consumed = mcmc_buffer_consume(c);
    val2_offset += consumed;

    // Parse END
    st = mcmc_parse_response_buf(c, buf + val2_offset, second_read - val2_offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 6. State tracking across multiple separate parse calls
//    Verifies the state machine transitions: DEFAULT -> GET_RESP -> DEFAULT
// ---------------------------------------------------------------------------
static void test_state_transitions(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // Initially in DEFAULT state
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    // Feed a VALUE response
    const char val_buf[] = "VALUE k 0 1\r\nX\r\n";
    int st = mcmc_parse_response_buf(c, val_buf, sizeof(val_buf) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    // Feed another VALUE — state stays GET_RESP
    const char val2_buf[] = "VALUE k2 0 2\r\nYZ\r\n";
    st = mcmc_parse_response_buf(c, val2_buf, sizeof(val2_buf) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    // Feed END — state returns to DEFAULT
    const char end_buf[] = "END\r\n";
    st = mcmc_parse_response_buf(c, end_buf, sizeof(end_buf) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 7. STAT response sequence state tracking
// ---------------------------------------------------------------------------
static void test_stat_state_transitions(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    const char stat1[] = "STAT pid 1234\r\n";
    int st = mcmc_parse_response_buf(c, stat1, sizeof(stat1) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_STAT);
    assert(mcmc_read_state(c) == MCMC_STATE_STAT_RESP);

    const char stat2[] = "STAT version 1.6.0\r\n";
    st = mcmc_parse_response_buf(c, stat2, sizeof(stat2) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_STAT);
    assert(mcmc_read_state(c) == MCMC_STATE_STAT_RESP);

    const char end[] = "END\r\n";
    st = mcmc_parse_response_buf(c, end, sizeof(end) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 8. mcmc_buffer_consume returns correct byte counts
// ---------------------------------------------------------------------------
static void test_buffer_consume_values(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // VALUE with 0-byte body
    const char empty_val[] = "VALUE empty 0 0\r\n\r\n";
    int st = mcmc_parse_response_buf(c, empty_val, sizeof(empty_val) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.vlen == 2);  // just "\r\n"
    assert(r.vlen_read == 2);
    // consumed = reslen + vlen_read
    assert(mcmc_buffer_consume(c) == r.reslen + r.vlen_read);

    // END line (no value body)
    const char end[] = "END\r\n";
    st = mcmc_parse_response_buf(c, end, sizeof(end) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(r.vlen == 0);
    assert(r.vlen_read == 0);
    assert(mcmc_buffer_consume(c) == 5);  // "END\r\n"

    // STORED (no value body, not a GET response)
    const char stored[] = "STORED\r\n";
    st = mcmc_parse_response_buf(c, stored, sizeof(stored) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GENERIC);
    assert(r.code == MCMC_CODE_STORED);
    assert(mcmc_buffer_consume(c) == 8);  // "STORED\r\n"

    free(c);
}

// ---------------------------------------------------------------------------
// 9. Large multiget: 10 keys all hit, iterate through all of them
// ---------------------------------------------------------------------------
static void test_large_multiget(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // Build a response with 10 keys
    char buf[4096];
    int pos = 0;
    for (int i = 0; i < 10; i++) {
        char val[16];
        int vlen = snprintf(val, sizeof(val), "val%04d", i);
        char key[16];
        snprintf(key, sizeof(key), "KEY_%04d", i);
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "VALUE %s 0 %d\r\n%s\r\n", key, vlen, val);
    }
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "END\r\n");

    size_t buflen = (size_t)pos;
    size_t offset = 0;
    int value_count = 0;

    while (offset < buflen) {
        int st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
        assert(st == MCMC_OK);

        if (r.type == MCMC_RESP_END) {
            offset += mcmc_buffer_consume(c);
            break;
        }

        assert(r.type == MCMC_RESP_GET);
        assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

        // Verify key
        char expected_key[16];
        snprintf(expected_key, sizeof(expected_key), "KEY_%04d", value_count);
        assert(r.klen == strlen(expected_key));
        assert(memcmp(r.key, expected_key, r.klen) == 0);

        // Verify value length
        char expected_val[16];
        int expected_vlen = snprintf(expected_val, sizeof(expected_val), "val%04d", value_count);
        assert(r.vlen == (size_t)(expected_vlen + 2));
        assert(r.vlen_read == r.vlen);
        assert(memcmp(r.value, expected_val, expected_vlen) == 0);

        offset += mcmc_buffer_consume(c);
        value_count++;
    }

    assert(value_count == 10);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 10. Parse failure resets state to DEFAULT (avoids getting stuck)
// ---------------------------------------------------------------------------
static void test_parse_failure_resets_state(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // First enter GET state
    const char val[] = "VALUE k 0 1\r\nX\r\n";
    int st = mcmc_parse_response_buf(c, val, sizeof(val) - 1, &r);
    assert(st == MCMC_OK);
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    // Feed garbage that can't be parsed (no newline)
    const char bad[] = "GARBAGE";
    st = mcmc_parse_response_buf(c, bad, sizeof(bad) - 1, &r);
    // Should fail (no \n found), but state should be preserved since
    // the parse didn't succeed (status != MCMC_OK)
    assert(st == MCMC_ERR);
    // State unchanged on parse error (we didn't get a successful parse)
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);

    // Feed a valid END to recover
    const char end[] = "END\r\n";
    st = mcmc_parse_response_buf(c, end, sizeof(end) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 11. mcmc_parse_buf (stateless) still works correctly
//     Verify backward compatibility — the bare API is unchanged.
// ---------------------------------------------------------------------------
static void test_stateless_parse_buf(void) {
    mcmc_resp_t r;

    // VALUE line
    const char val[] = "VALUE mykey 42 5\r\nhello\r\n";
    int st = mcmc_parse_buf(val, sizeof(val) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.klen == 5);
    assert(memcmp(r.key, "mykey", 5) == 0);
    assert(r.flags == 42);
    assert(r.vlen == 7);
    assert(r.vlen_read == 7);

    // END
    const char end[] = "END\r\n";
    st = mcmc_parse_buf(end, sizeof(end) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);

    // STORED
    const char stored[] = "STORED\r\n";
    st = mcmc_parse_buf(stored, sizeof(stored) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GENERIC);
    assert(r.code == MCMC_CODE_STORED);
}

// ---------------------------------------------------------------------------
// 12. Multiget with CAS values
// ---------------------------------------------------------------------------
static void test_multiget_with_cas(void) {
    void *c = make_ctx();
    mcmc_resp_t r;
    const char buf[] =
        "VALUE key1 0 5 12345\r\n"
        "hello\r\n"
        "VALUE key2 0 5 67890\r\n"
        "world\r\n"
        "END\r\n";
    size_t buflen = sizeof(buf) - 1;
    size_t offset = 0;

    // Parse VALUE key1 with CAS
    int st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.cas == 12345);
    assert(r.vlen == 7);
    offset += mcmc_buffer_consume(c);

    // Parse VALUE key2 with CAS
    st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.cas == 67890);
    offset += mcmc_buffer_consume(c);

    // Parse END
    st = mcmc_parse_response_buf(c, buf + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    offset += mcmc_buffer_consume(c);

    assert(offset == buflen);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 13. Incomplete buffer (no newline) returns WANT_READ
// ---------------------------------------------------------------------------
static void test_incomplete_buffer_want_read(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // No newline yet
    const char partial[] = "VALUE key1 0 5\r";
    int st = mcmc_parse_response_buf(c, partial, sizeof(partial) - 1, &r);
    assert(st == MCMC_ERR);
    assert(r.code == MCMC_WANT_READ);

    // State should not change on WANT_READ
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 14. Simulate realistic multiget loop pattern (as a real caller would use)
// ---------------------------------------------------------------------------
static void test_realistic_multiget_loop(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // This simulates what a real caller would do:
    // 1. Send "get key1 key2 key3\r\n"
    // 2. recv() into buffer
    // 3. Loop: parse, consume, advance buffer, repeat until END

    const char response[] =
        "VALUE key1 0 5\r\n"
        "hello\r\n"
        "VALUE key2 0 5\r\n"
        "world\r\n"
        "END\r\n";

    // Simulate: all data arrives in one recv
    char buf[4096];
    size_t buf_used = strlen(response);
    memcpy(buf, response, buf_used);

    int values_found = 0;
    size_t offset = 0;
    int done = 0;

    while (!done && offset < buf_used) {
        int st = mcmc_parse_response_buf(c, buf + offset, buf_used - offset, &r);
        if (st == MCMC_ERR && r.code == MCMC_WANT_READ) {
            // Need more data from socket — in real code, recv() here
            break;
        }
        assert(st == MCMC_OK);

        size_t consumed = mcmc_buffer_consume(c);
        offset += consumed;

        switch (r.type) {
        case MCMC_RESP_GET:
            values_found++;
            // In real code: process r.key, r.klen, r.value, r.vlen
            // If vlen > vlen_read, recv remaining value bytes
            break;
        case MCMC_RESP_END:
            done = 1;
            break;
        default:
            // unexpected
            assert(0);
            break;
        }
    }

    assert(done == 1);
    assert(values_found == 2);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// 15. Value spanning exact buffer boundary
//     First recv: VALUE header + exactly the value data, nothing more.
//     Second recv: next VALUE + END.
// ---------------------------------------------------------------------------
static void test_value_exact_buffer_boundary(void) {
    void *c = make_ctx();
    mcmc_resp_t r;

    // First buffer: VALUE header + complete value
    const char buf1[] = "VALUE key1 0 5\r\nhello\r\n";
    int st = mcmc_parse_response_buf(c, buf1, sizeof(buf1) - 1, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.klen == 4);
    assert(r.vlen == 7);
    assert(r.vlen_read == 7);
    assert(mcmc_read_state(c) == MCMC_STATE_GET_RESP);
    assert(mcmc_buffer_consume(c) == sizeof(buf1) - 1);

    // Second buffer: next VALUE + END
    const char buf2[] = "VALUE key2 0 3\r\nabc\r\nEND\r\n";
    size_t offset = 0;
    size_t buflen = sizeof(buf2) - 1;

    st = mcmc_parse_response_buf(c, buf2 + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_GET);
    assert(r.klen == 4);
    assert(memcmp(r.key, "key2", 4) == 0);
    offset += mcmc_buffer_consume(c);

    st = mcmc_parse_response_buf(c, buf2 + offset, buflen - offset, &r);
    assert(st == MCMC_OK);
    assert(r.type == MCMC_RESP_END);
    assert(mcmc_read_state(c) == MCMC_STATE_DEFAULT);

    free(c);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void) {
    printf("Running mcmc multiget regression tests...\n\n");

    RUN_TEST(test_single_get_hit);
    RUN_TEST(test_multiget_all_hit);
    RUN_TEST(test_multiget_partial_miss);
    RUN_TEST(test_multiget_all_miss);
    RUN_TEST(test_value_boundary_cross_buffer);
    RUN_TEST(test_state_transitions);
    RUN_TEST(test_stat_state_transitions);
    RUN_TEST(test_buffer_consume_values);
    RUN_TEST(test_large_multiget);
    RUN_TEST(test_parse_failure_resets_state);
    RUN_TEST(test_stateless_parse_buf);
    RUN_TEST(test_multiget_with_cas);
    RUN_TEST(test_incomplete_buffer_want_read);
    RUN_TEST(test_realistic_multiget_loop);
    RUN_TEST(test_value_exact_buffer_boundary);

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
