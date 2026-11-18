#ifndef BDC2_SHA256_H
#define BDC2_SHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t klen,
                 const void *data, size_t dlen, uint8_t out[32]);

/* RFC5869 HKDF-SHA256, single info string. Returns 0 on success. */
int hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                const uint8_t *salt, size_t saltlen,
                const char *info, uint8_t *out, size_t outlen);

#endif
