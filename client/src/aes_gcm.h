#ifndef BDC2_AES_GCM_H
#define BDC2_AES_GCM_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t rk[176];
} aes128_ctx;

void aes128_init(aes128_ctx *ctx, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

/* AES-128-GCM. nonce must be 12 bytes. Returns 0 on success, -1 on tag error. */
int aes_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *pt, size_t ptlen,
                    uint8_t *ct, uint8_t tag[16]);

int aes_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen,
                    uint8_t *pt, const uint8_t tag[16]);

#endif
