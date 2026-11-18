#include "ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include <ws2tcpip.h>

int net_wsa_init(void) {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w);
}

static int ws_rand_bytes(uint8_t *buf, int len) {
    HCRYPTPROV p;
    if (!CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(p, (DWORD)len, buf);
    CryptReleaseContext(p, 0);
    return ok ? 0 : -1;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_encode(const uint8_t *in, int inlen, char *out, int outcap) {
    int o = 0;
    for (int i = 0; i < inlen; i += 3) {
        int n = inlen - i;
        uint32_t v = (uint32_t)in[i] << 16;
        if (n > 1) v |= (uint32_t)in[i + 1] << 8;
        if (n > 2) v |= in[i + 2];
        if (o + 4 >= outcap) return -1;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = n > 1 ? B64[(v >> 6) & 63] : '=';
        out[o++] = n > 2 ? B64[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int b64_decode(const char *in, uint8_t *out, int outcap) {
    int o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\r' || *p == '\n' || *p == ' ') break;
        int v = b64_val(*p);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outcap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_psk(const char *s, uint8_t *out, int outcap, int *outlen) {
    if (!s) return -1;
    if (strncmp(s, "base64:", 7) == 0) {
        int n = b64_decode(s + 7, out, outcap);
        if (n <= 0) return -1;
        *outlen = n;
        return 0;
    }
    if (strncmp(s, "hex:", 4) == 0) s += 4;
    size_t l = strlen(s);
    if (l >= 32 && l % 2 == 0) {
        int n = (int)(l / 2);
        if (n > outcap) return -1;
        for (int i = 0; i < n; i++) {
            int hi = hexval(s[i * 2]), lo = hexval(s[i * 2 + 1]);
            if (hi < 0 || lo < 0) return -1;
            out[i] = (uint8_t)(hi << 4 | lo);
        }
        *outlen = n;
        return 0;
    }
    int n = b64_decode(s, out, outcap);
    if (n <= 0) return -1;
    *outlen = n;
    return 0;
}

static void set_timeout(SOCKET s, int ms) {
    DWORD tv = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
}

SOCKET net_connect(const char *host, int port, int timeout_ms) {
    char portstr[16];
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return INVALID_SOCKET;
    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(s);
                s = INVALID_SOCKET;
                continue;
            }
            fd_set wf, ef;
            FD_ZERO(&wf);
            FD_ZERO(&ef);
            FD_SET(s, &wf);
            FD_SET(s, &ef);
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sel = select(0, NULL, &wf, &ef, &tv);
            if (sel <= 0 || FD_ISSET(s, &ef)) {
                closesocket(s);
                s = INVALID_SOCKET;
                continue;
            }
        }
        nb = 0;
        ioctlsocket(s, FIONBIO, &nb);
        set_timeout(s, 15000);
        break;
    }
    freeaddrinfo(res);
    return s;
}

static int send_all(SOCKET s, const void *data, size_t len) {
    const char *p = (const char *)data;
    while (len) {
        int n = send(s, p, (int)len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_all(SOCKET s, void *data, size_t len) {
    char *p = (char *)data;
    while (len) {
        int n = recv(s, p, (int)len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int ws_handshake(SOCKET s, const char *host, int port, const char *path) {
    uint8_t key[16];
    char b64key[32];
    if (ws_rand_bytes(key, 16) != 0) return -1;
    if (b64_encode(key, 16, b64key, sizeof(b64key)) < 0) return -1;
    char req[512];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n\r\n",
                     path, host, port, b64key);
    if (n <= 0 || n >= (int)sizeof(req)) return -1;
    if (send_all(s, req, (size_t)n) != 0) return -1;

    char resp[2048];
    size_t got = 0;
    while (got < sizeof(resp) - 1) {
        int r = recv(s, resp + got, (int)(sizeof(resp) - 1 - got), 0);
        if (r <= 0) return -1;
        got += (size_t)r;
        resp[got] = 0;
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (!strstr(resp, " 101 ")) return -1;
    return 0;
}

int ws_send(ws_conn *c, int opcode, const uint8_t *data, size_t len) {
    uint8_t hdr[14];
    size_t h = 0;
    hdr[h++] = (uint8_t)(0x80 | (opcode & 0x0f));
    uint8_t mbit = c->mask ? 0x80 : 0;
    if (len < 126) {
        hdr[h++] = (uint8_t)(mbit | (uint8_t)len);
    } else if (len <= 0xffff) {
        hdr[h++] = (uint8_t)(mbit | 126);
        hdr[h++] = (uint8_t)(len >> 8);
        hdr[h++] = (uint8_t)len;
    } else {
        hdr[h++] = (uint8_t)(mbit | 127);
        for (int i = 7; i >= 0; i--) hdr[h++] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    if (c->mask) {
        uint8_t mk[4];
        if (ws_rand_bytes(mk, 4) != 0) return -1;
        memcpy(hdr + h, mk, 4);
        h += 4;
        if (send_all(c->s, hdr, h) != 0) return -1;
        uint8_t *tmp = (uint8_t *)malloc(len ? len : 1);
        if (!tmp) return -1;
        for (size_t i = 0; i < len; i++) tmp[i] = data[i] ^ mk[i & 3];
        int rc = send_all(c->s, tmp, len);
        free(tmp);
        return rc;
    }
    if (send_all(c->s, hdr, h) != 0) return -1;
    return len ? send_all(c->s, data, len) : 0;
}

int ws_wait(ws_conn *c, int timeout_ms) {
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(c->s, &rf);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(0, &rf, NULL, NULL, &tv);
    if (r < 0) return -1;
    return r > 0 ? 1 : 0;
}

static int read_frame(ws_conn *c, int *opcode, uint8_t **out, size_t *outlen) {
    uint8_t h[2];
    if (recv_all(c->s, h, 2) != 0) return -1;
    int fin = (h[0] & 0x80) != 0;
    int op = h[0] & 0x0f;
    int masked = (h[1] & 0x80) != 0;
    uint64_t n = h[1] & 0x7f;
    if (n == 126) {
        uint8_t e[2];
        if (recv_all(c->s, e, 2) != 0) return -1;
        n = ((uint64_t)e[0] << 8) | e[1];
    } else if (n == 127) {
        uint8_t e[8];
        if (recv_all(c->s, e, 8) != 0) return -1;
        n = 0;
        for (int i = 0; i < 8; i++) n = (n << 8) | e[i];
    }
    if (n > 8u * 1024 * 1024) return -1;
    uint8_t mk[4] = {0, 0, 0, 0};
    if (masked && recv_all(c->s, mk, 4) != 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    if (!buf) return -1;
    if (n && recv_all(c->s, buf, (size_t)n) != 0) {
        free(buf);
        return -1;
    }
    if (masked) {
        for (uint64_t i = 0; i < n; i++) buf[i] ^= mk[i & 3];
    }
    if (op == 0x9) { /* ping */
        ws_send(c, 0xA, buf, (size_t)n);
        free(buf);
        return 2;
    }
    if (op == 0xA) { /* pong */
        free(buf);
        return 2;
    }
    if (op == 0x8) { /* close */
        free(buf);
        return -1;
    }
    if (!fin) {
        /* Fragmented message: accumulate. */
        size_t total = (size_t)n;
        uint8_t *acc = buf;
        int first_op = op;
        for (;;) {
            uint8_t h2[2];
            if (recv_all(c->s, h2, 2) != 0) {
                free(acc);
                return -1;
            }
            int fin2 = (h2[0] & 0x80) != 0;
            int op2 = h2[0] & 0x0f;
            int m2 = (h2[1] & 0x80) != 0;
            uint64_t n2 = h2[1] & 0x7f;
            if (n2 == 126) {
                uint8_t e[2];
                recv_all(c->s, e, 2);
                n2 = ((uint64_t)e[0] << 8) | e[1];
            } else if (n2 == 127) {
                uint8_t e[8];
                recv_all(c->s, e, 8);
                n2 = 0;
                for (int i = 0; i < 8; i++) n2 = (n2 << 8) | e[i];
            }
            if (total + n2 > 8u * 1024 * 1024) {
                free(acc);
                return -1;
            }
            uint8_t mk2[4] = {0, 0, 0, 0};
            if (m2) recv_all(c->s, mk2, 4);
            acc = (uint8_t *)realloc(acc, total + (size_t)n2);
            if (!acc) return -1;
            if (n2 && recv_all(c->s, acc + total, (size_t)n2) != 0) {
                free(acc);
                return -1;
            }
            if (m2) {
                for (uint64_t i = 0; i < n2; i++) acc[total + i] ^= mk2[i & 3];
            }
            total += (size_t)n2;
            if (fin2) {
                *opcode = op2 == 0 ? first_op : op2;
                *out = acc;
                *outlen = total;
                return 1;
            }
        }
    }
    *opcode = op;
    *out = buf;
    *outlen = (size_t)n;
    return 1;
}

int ws_recv(ws_conn *c, int *opcode, uint8_t **out, size_t *outlen) {
    for (;;) {
        int r = read_frame(c, opcode, out, outlen);
        if (r == 2) continue;
        return r;
    }
}
