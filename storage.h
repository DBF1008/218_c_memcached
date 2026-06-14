#ifndef STORAGE_H
#define STORAGE_H

void storage_delete(void *e, item *it);
#ifdef EXTSTORE
#define STORAGE_delete(e, it) \
    do { \
        storage_delete(e, it); \
    } while (0)
#else
#define STORAGE_delete(...)
#endif

// API.
void storage_stats(ADD_STAT add_stats, void *c);
void process_extstore_stats(ADD_STAT add_stats, void *c);
bool storage_validate_item(void *e, item *it);
#ifdef EXTSTORE
// Return codes for storage_get_item():
#define STORAGE_GET_OK          0   // IO queued successfully
#define STORAGE_GET_OOM        -1   // Memory allocation failure (item, chunk, or iov malloc)
#define STORAGE_GET_OVERSIZED  -2   // Item requires more iovec slots than IOV_MAX allows
int storage_get_item(LIBEVENT_THREAD *t, item *it, mc_resp *resp);
#else
#define storage_get_item NULL
#endif

// callback for the IO queue subsystem.
void storage_submit_cb(io_queue_t *q);

// Thread functions.
int start_storage_write_thread(void *arg);
void storage_write_pause(void);
void storage_write_resume(void);
int start_storage_compact_thread(void *arg);
void storage_compact_pause(void);
void storage_compact_resume(void);

// Init functions.
struct extstore_conf_file *storage_conf_parse(char *arg);
void *storage_init_config(struct settings *s);
int storage_read_config(void *conf, char **subopt);
int storage_check_config(void *conf);
void *storage_init(void *conf);

// Ignore pointers and header bits from the CRC
#define STORE_OFFSET offsetof(item, nbytes)

#endif
