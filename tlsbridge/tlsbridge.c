/* tlsbridge.c - tiny TLS1.2 -> TCP (plaintext) bridge for Windows Server 2008 x64.
 *
 * Listens on a local TCP port (plaintext); for each accepted connection it opens
 * a TLS1.2 session to a remote host (SNI configurable) and relays bytes both
 * ways.  Gives a plaintext-only WebSocket client a TLS path to Cloudflare without
 * relying on the OS SChannel / .NET stack (absent on Server 2008 SP1).
 *
 * Build (MinGW-w64 msvcrt, static mbedTLS):
 *   x86_64-w64-mingw32-gcc -O2 -s -static -static-libgcc \
 *     -D_WIN32_WINNT=0x0600 -DWINVER=0x0600 tlsbridge.c -o tlsbridge.exe \
 *     -lmbedtls -lmbedx509 -lmbedcrypto -lws2_32
 *
 * Usage:
 *   tlsbridge.exe --listen 127.0.0.1:1443 --connect <origin-ip>:443 \
 *                 --sni <origin-hostname> [--log C:\Windows\Temp\c2bridge.log]
 *   tlsbridge.exe --selftest --connect <origin-ip>:443 --sni <origin-hostname>
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"

static FILE *g_log = NULL;

static void lg(const char *fmt, ...) {
    va_list ap, ap2;
    char ts[32];
    time_t t = time(NULL);
    struct tm *tmv = localtime(&t);
    if (tmv) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tmv);
    else strcpy(ts, "-");
    va_start(ap, fmt);
    va_copy(ap2, ap);
    if (g_log) { fprintf(g_log, "%s ", ts); vfprintf(g_log, fmt, ap); fprintf(g_log, "\n"); fflush(g_log); }
    printf("%s ", ts); vprintf(fmt, ap2); printf("\n"); fflush(stdout);
    va_end(ap2);
    va_end(ap);
}

typedef struct {
    char listen_addr[64];
    int  listen_port;
    char conn_host[128];
    int  conn_port;
    char sni[256];
    int  selftest;
} cfg_t;

static int parse_hostport(const char *s, char *host, size_t hcap, int *port) {
    const char *c = strrchr(s, ':');
    size_t n;
    if (!c) return -1;
    n = (size_t)(c - s);
    if (n == 0 || n >= hcap) return -1;
    memcpy(host, s, n); host[n] = 0;
    *port = atoi(c + 1);
    return (*port > 0 && *port < 65536) ? 0 : -1;
}

/* connect + TLS1.2 handshake; caller frees. returns 0 ok */
static int tls_up(mbedtls_net_context *srv, mbedtls_ssl_context *ssl,
                  mbedtls_ssl_config *conf, mbedtls_ctr_drbg_context *drbg,
                  mbedtls_entropy_context *ent, const cfg_t *cfg)
{
    int ret, loops = 0;
    char errbuf[160], portstr[16];
    static const char *pers = "bdc2-tlsbridge";
    snprintf(portstr, sizeof(portstr), "%d", cfg->conn_port);

    mbedtls_net_init(srv);
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(drbg);
    mbedtls_entropy_init(ent);

    if ((ret = mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, ent,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        lg("ctr_drbg_seed failed -0x%04x", -ret); return ret;
    }
    if ((ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        lg("ssl_config_defaults failed -0x%04x", -ret); return ret;
    }
#ifdef MBEDTLS_SSL_PROTO_TLS1_2
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, drbg);

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
        lg("ssl_setup failed -0x%04x", -ret); return ret;
    }
    if (cfg->sni[0] && (ret = mbedtls_ssl_set_hostname(ssl, cfg->sni)) != 0) {
        lg("set_hostname(%s) failed -0x%04x", cfg->sni, -ret); return ret;
    }
    if ((ret = mbedtls_net_connect(srv, cfg->conn_host, portstr,
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        lg("net_connect(%s:%s) failed -0x%04x (%s)", cfg->conn_host, portstr, -ret, errbuf);
        return ret;
    }
    mbedtls_ssl_set_bio(ssl, srv, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            lg("TLS handshake failed -0x%04x (%s)", -ret, errbuf);
            return ret;
        }
        if (++loops > 120000) { lg("TLS handshake stalled"); return -1; }
    }
    lg("TLS up: %s %s sni=%s peer=%s:%d",
       mbedtls_ssl_get_version(ssl), mbedtls_ssl_get_ciphersuite(ssl),
       cfg->sni[0] ? cfg->sni : "-", cfg->conn_host, cfg->conn_port);
    return 0;
}

static void tls_down(mbedtls_net_context *srv, mbedtls_ssl_context *ssl,
                     mbedtls_ssl_config *conf, mbedtls_ctr_drbg_context *drbg,
                     mbedtls_entropy_context *ent)
{
    mbedtls_ssl_close_notify(ssl);
    mbedtls_net_free(srv);
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(conf);
    mbedtls_ctr_drbg_free(drbg);
    mbedtls_entropy_free(ent);
}

static int send_all(SOCKET s, const unsigned char *p, int n) {
    while (n > 0) {
        int w = send(s, (const char *)p, n, 0);
        if (w <= 0) return -1;
        p += w; n -= w;
    }
    return 0;
}

static int tls_write_all(mbedtls_ssl_context *ssl, const unsigned char *p, int n) {
    while (n > 0) {
        int w = mbedtls_ssl_write(ssl, p, (size_t)n);
        if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (w <= 0) return -1;
        p += w; n -= w;
    }
    return 0;
}

static void relay(SOCKET cli, mbedtls_net_context *srv, mbedtls_ssl_context *ssl)
{
    unsigned char buf[16384];
    int idle = 0;
    for (;;) {
        fd_set rf;
        struct timeval tv;
        int sel, avail;
        FD_ZERO(&rf);
        FD_SET(cli, &rf);
        FD_SET((SOCKET)srv->fd, &rf);
        tv.tv_sec = 5; tv.tv_usec = 0;
        sel = select(0, &rf, NULL, NULL, &tv);
        if (sel == SOCKET_ERROR) { lg("select failed %d", WSAGetLastError()); break; }

        /* drain decrypted TLS data first (may be buffered inside mbedtls) */
        avail = (int)mbedtls_ssl_get_bytes_avail(ssl);
        if (avail > 0 || (sel > 0 && FD_ISSET((SOCKET)srv->fd, &rf))) {
            int n = mbedtls_ssl_read(ssl, buf, sizeof(buf));
            if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) { /* retry */ }
            else if (n <= 0) { lg("tls->local closed (%d)", n); break; }
            else { if (send_all(cli, buf, n) != 0) { lg("local send failed"); break; } idle = 0; }
        }
        if (sel > 0 && FD_ISSET(cli, &rf)) {
            int n = recv(cli, (char *)buf, sizeof(buf), 0);
            if (n <= 0) { lg("local->tls closed (%d)", n); break; }
            if (tls_write_all(ssl, buf, n) != 0) { lg("tls write failed"); break; }
            idle = 0;
        } else if (sel == 0) {
            if (++idle >= 240) { lg("relay idle timeout"); break; }
        }
    }
}

static int selftest(const cfg_t *cfg)
{
    mbedtls_net_context srv; mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context drbg; mbedtls_entropy_context ent;
    int ret;
    ret = tls_up(&srv, &ssl, &conf, &drbg, &ent, cfg);
    if (ret == 0) {
        /* send a plain HTTP request through TLS to prove the path */
        const char *req = "GET /healthz HTTP/1.0\r\nHost: ";
        char full[512];
        unsigned char rb[512];
        int n;
        snprintf(full, sizeof(full), "%s%s\r\nConnection: close\r\n\r\n", req,
                 cfg->sni[0] ? cfg->sni : cfg->conn_host);
        if (tls_write_all(&ssl, (const unsigned char *)full, (int)strlen(full)) == 0) {
            n = mbedtls_ssl_read(&ssl, rb, sizeof(rb) - 1);
            if (n > 0) { rb[n] = 0; lg("SELFTEST response: %.120s", (char *)rb); }
            else lg("SELFTEST read ret -0x%04x", -n);
        }
        tls_down(&srv, &ssl, &conf, &drbg, &ent);
        return 0;
    }
    tls_down(&srv, &ssl, &conf, &drbg, &ent);
    return 1;
}

int main(int argc, char **argv)
{
    cfg_t cfg; WSADATA wsa; SOCKET ls; struct sockaddr_in sa;
    int i, one = 1;

    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.listen_addr, "127.0.0.1");
    cfg.listen_port = 1443;
    cfg.conn_host[0] = 0;
    cfg.conn_port = 443;
    cfg.sni[0] = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--listen") && i + 1 < argc) {
            if (parse_hostport(argv[++i], cfg.listen_addr, sizeof(cfg.listen_addr), &cfg.listen_port)) return 2;
        } else if (!strcmp(argv[i], "--connect") && i + 1 < argc) {
            if (parse_hostport(argv[++i], cfg.conn_host, sizeof(cfg.conn_host), &cfg.conn_port)) return 2;
        } else if (!strcmp(argv[i], "--sni") && i + 1 < argc) {
            snprintf(cfg.sni, sizeof(cfg.sni), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--log") && i + 1 < argc) {
            g_log = fopen(argv[++i], "a");
        } else if (!strcmp(argv[i], "--selftest")) {
            cfg.selftest = 1;
        } else { printf("unknown/incomplete arg: %s\n", argv[i]); return 2; }
    }

    if (!cfg.conn_host[0] || !cfg.sni[0]) {
        printf("usage: tlsbridge.exe --listen 127.0.0.1:1443 --connect <ip>:443 --sni <host> [--log <file>]\n");
        return 2;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup failed\n"); return 3; }
    lg("tlsbridge start listen=%s:%d connect=%s:%d sni=%s", cfg.listen_addr, cfg.listen_port,
       cfg.conn_host, cfg.conn_port, cfg.sni);

    if (cfg.selftest) { int rc = selftest(&cfg); lg("selftest rc=%d", rc); return rc; }

    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) { lg("socket failed"); return 3; }
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)cfg.listen_port);
    sa.sin_addr.s_addr = inet_addr(cfg.listen_addr);
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0) { lg("bind failed %d", WSAGetLastError()); return 4; }
    if (listen(ls, 8) != 0) { lg("listen failed %d", WSAGetLastError()); return 4; }
    lg("listening %s:%d", cfg.listen_addr, cfg.listen_port);

    for (;;) {
        struct sockaddr_in ca; int clen = sizeof(ca);
        SOCKET cli = accept(ls, (struct sockaddr *)&ca, &clen);
        mbedtls_net_context srv; mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
        mbedtls_ctr_drbg_context drbg; mbedtls_entropy_context ent;
        if (cli == INVALID_SOCKET) { Sleep(200); continue; }
        lg("local conn from %s:%d", inet_ntoa(ca.sin_addr), ntohs(ca.sin_port));
        if (tls_up(&srv, &ssl, &conf, &drbg, &ent, &cfg) == 0) {
            relay(cli, &srv, &ssl);
        }
        tls_down(&srv, &ssl, &conf, &drbg, &ent);
        shutdown(cli, SD_BOTH);
        closesocket(cli);
        lg("local conn closed");
    }
    return 0;
}
