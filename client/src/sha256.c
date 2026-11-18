#include "sha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BS0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define BS1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SS0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SS1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void compress(sha256_ctx *c, const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++)
        w[i] = SS1(w[i - 2]) + w[i - 7] + SS0(w[i - 15]) + w[i - 16];
    uint32_t a = c->h[0], b = c->h[1], d = c->h[3], e = c->h[4];
    uint32_t f = c->h[5], g = c->h[6], h = c->h[7], cc = c->h[2];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BS1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BS0(a) + MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

void sha256_init(sha256_ctx *c) {
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->total = 0;
    c->buflen = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    c->total += len;
    if (c->buflen) {
        size_t n = 64 - c->buflen;
        if (n > len) n = len;
        memcpy(c->buf + c->buflen, p, n);
        c->buflen += n;
        p += n;
        len -= n;
        if (c->buflen == 64) {
            compress(c, c->buf);
            c->buflen = 0;
        }
    }
    while (len >= 64) {
        compress(c, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->buflen = len;
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 56) sha256_update(c, &z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

void sha256(const void *data, size_t len, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t klen, const void *data, size_t dlen,
                 uint8_t out[32]) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (klen > 64) {
        sha256(key, klen, k);
    } else {
        memcpy(k, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha256_ctx c;
    uint8_t inner[32];
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, data, dlen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

int hkdf_sha256(const uint8_t *ikm, size_t ikmlen, const uint8_t *salt,
                size_t saltlen, const char *info, uint8_t *out, size_t outlen) {
    uint8_t prk[32], t[32];
    if (outlen > 255 * 32) return -1;
    hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    size_t done = 0, tlen = 0;
    uint8_t counter = 1;
    while (done < outlen) {
        sha256_ctx c; /* HMAC(prk, T | info | counter) built manually */
        uint8_t k[64];
        memset(k, 0, 64);
        memcpy(k, prk, 32);
        uint8_t ipad[64], opad[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        uint8_t inner[32];
        sha256_init(&c);
        sha256_update(&c, ipad, 64);
        if (tlen) sha256_update(&c, t, tlen);
        sha256_update(&c, info, strlen(info));
        sha256_update(&c, &counter, 1);
        sha256_final(&c, inner);
        sha256_init(&c);
        sha256_update(&c, opad, 64);
        sha256_update(&c, inner, 32);
        sha256_final(&c, t);
        tlen = 32;
        size_t n = outlen - done < 32 ? outlen - done : 32;
        memcpy(out + done, t, n);
        done += n;
        counter++;
    }
    return 0;
}
