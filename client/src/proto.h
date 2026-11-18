#ifndef C2_PROTO_H
#define C2_PROTO_H
#include "common.h"
#include "util.h"

#define PROTO_HDR_LEN   12
#define PROTO_FLAG_ENC  0x0001

/* message types */
#define MSG_S_HELLO        0x01
#define MSG_C_HELLO        0x02
#define MSG_C_REGISTER     0x03
#define MSG_S_REGISTER_OK  0x04
#define MSG_TASK           0x10
#define MSG_TASK_RESULT    0x11
#define MSG_PING           0x20
#define MSG_PONG           0x21
#define MSG_FILE_CHUNK     0x30
#define MSG_FILE_ACK       0x31
#define MSG_TUNNEL_OPEN    0x40
#define MSG_TUNNEL_DATA    0x41
#define MSG_TUNNEL_CLOSE   0x42
#define MSG_SESSION_REKEY  0x50
#define MSG_ERROR          0x7F

typedef struct {
    int  established;
    u8   c2s_key[32];
    u8   s2c_key[32];
    u8   iv[8];
    u32  tx_seq;
    u32  rx_seq;
    u8   sid[16];
} session_t;

void session_init(session_t *s);
int  session_derive(session_t *s, const u8 shared[32],
                    const u8 *psk, size_t psklen,
                    const u8 *salt, size_t saltlen,
                    const u8 *info, size_t infolen);

int  proto_pack(session_t *s, u8 type, u16 flags,
                const void *payload, size_t len, buf_t *out);
int  proto_unpack(session_t *s, const u8 *data, size_t len,
                  u8 *type, u16 *flags, buf_t *payload);

#endif
