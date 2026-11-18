#ifndef C2_UTIL_H
#define C2_UTIL_H
#include "common.h"

/* growable byte buffer */
typedef struct {
    u8    *data;
    size_t len;
    size_t cap;
} buf_t;

void  buf_init(buf_t *b);
void  buf_free(buf_t *b);
void  buf_reset(buf_t *b);
int   buf_reserve(buf_t *b, size_t need);
int   buf_append(buf_t *b, const void *p, size_t n);
int   buf_append_str(buf_t *b, const char *s);
int   buf_append_printf(buf_t *b, const char *fmt, ...);
int   buf_set(buf_t *b, const void *p, size_t n);
void  buf_consume(buf_t *b, size_t n);

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t s);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

u64   now_ms(void);
void  sleep_ms(unsigned ms);

char *hex_enc(const u8 *in, size_t n);
int   hex_dec(const char *in, u8 **out, size_t *outlen);
char *b64_enc(const u8 *in, size_t n);
int   b64_dec(const char *in, u8 **out, size_t *outlen);

int   read_file(const char *path, buf_t *out);
int   write_file(const char *path, const void *data, size_t len, int append);
int   path_exists(const char *path);
char *exe_path(void);
char *exe_dir(void);
char *path_join(const char *dir, const char *name);
int   mkdir_p(const char *path);

wchar_t *widen(const char *s);
char    *narrow(const wchar_t *s);

/* Run a command through cmd.exe /c with stdout+stderr captured, hidden window. */
int   run_cmd(const char *cmdline, buf_t *out, int timeout_ms, int *exit_code);
/* Run an arbitrary command line (needs a real exe) without shell. */
int   run_proc(const wchar_t *cmdline, buf_t *out, int timeout_ms, int *exit_code);

void  log_init(const char *path, int debug);
void  log_close(void);
void  LOGF(const char *fmt, ...);

/* Random helpers backed by the crypto layer (weak fallback if not initialised). */
void  rand_bytes(void *out, size_t n);
void  rand_hex(char *out, size_t nbytes);

/* Simple case-insensitive compare */
int   ci_eq(const char *a, const char *b);

/* Get environment variable into malloc'd string (NULL if unset) */
char *env_dup(const char *name);

#endif /* C2_UTIL_H */
