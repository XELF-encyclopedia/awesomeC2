#ifndef BDC2_WS_H
#define BDC2_WS_H

#include <stddef.h>
#include <stdint.h>
#include <winsock2.h>

typedef struct {
    SOCKET s;
    int mask; /* client side = 1 */
} ws_conn;

int net_wsa_init(void);
SOCKET net_connect(const char *host, int port, int timeout_ms);
int ws_handshake(SOCKET s, const char *host, int port, const char *path);
int ws_send(ws_conn *c, int opcode, const uint8_t *data, size_t len);
/* Returns: 1 = message, 0 = timeout, -1 = error. *out is malloc'ed. */
int ws_recv(ws_conn *c, int *opcode, uint8_t **out, size_t *outlen);
int ws_wait(ws_conn *c, int timeout_ms);

/* rand_bytes() lives in util.c (void rand_bytes(void*, size_t)). */
int b64_encode(const uint8_t *in, int inlen, char *out, int outcap);
int b64_decode(const char *in, uint8_t *out, int outcap);
int parse_psk(const char *s, uint8_t *out, int outcap, int *outlen);

#endif
