
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "export.h"
#include "utils.h"
#include "crypto_stream_chacha20.h"
#include "stream_chacha20_vec.h"
#include "../stream_chacha20.h"

#if (defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H) && defined(__GNUC__))

#pragma GCC target("sse2")
#pragma GCC target("ssse3")

#define CHACHA_RNDS 20

typedef unsigned int vec __attribute__((vector_size(16)));

#include <emmintrin.h>
#include <tmmintrin.h>

# if __clang__
#  define VBPI 4
# else
#  define VBPI 3
# endif
# define ONE (vec) _mm_set_epi32(0, 0, 0, 1)
# define LOAD(m) (vec) _mm_loadu_si128((const __m128i *) (const void *) (m))
# define LOAD_ALIGNED(m) (vec) _mm_load_si128((const __m128i *) (const void *) (m))
# define STORE(m, r) _mm_storeu_si128((__m128i *) (void *) (m), (__m128i) (r))
# define ROTV1(x) (vec) _mm_shuffle_epi32((__m128i)x, _MM_SHUFFLE(0, 3, 2, 1))
# define ROTV2(x) (vec) _mm_shuffle_epi32((__m128i)x, _MM_SHUFFLE(1, 0, 3, 2))
# define ROTV3(x) (vec) _mm_shuffle_epi32((__m128i)x, _MM_SHUFFLE(2, 1, 0, 3))
# define ROTW7(x) \
    (vec)(_mm_slli_epi32((__m128i)x, 7) ^ _mm_srli_epi32((__m128i)x, 25))
# define ROTW12(x) \
    (vec)(_mm_slli_epi32((__m128i)x, 12) ^ _mm_srli_epi32((__m128i)x, 20))
# define ROTW8(x) \
    (vec)(_mm_slli_epi32((__m128i)x, 8) ^ _mm_srli_epi32((__m128i)x, 24))
#define ROTW16(x) \
    (vec)(_mm_slli_epi32((__m128i)x, 16) ^ _mm_srli_epi32((__m128i)x, 16))

#ifndef REVV_BE
# define REVV_BE(x) (x)
#endif

#define BPI (VBPI + 0) /* Blocks computed per loop iteration   */

#define DQROUND_VECTORS(a, b, c, d) \
    a += b;                         \
    d ^= a;                         \
    d = ROTW16(d);                  \
    c += d;                         \
    b ^= c;                         \
    b = ROTW12(b);                  \
    a += b;                         \
    d ^= a;                         \
    d = ROTW8(d);                   \
    c += d;                         \
    b ^= c;                         \
    b = ROTW7(b);                   \
    b = ROTV1(b);                   \
    c = ROTV2(c);                   \
    d = ROTV3(d);                   \
    a += b;                         \
    d ^= a;                         \
    d = ROTW16(d);                  \
    c += d;                         \
    b ^= c;                         \
    b = ROTW12(b);                  \
    a += b;                         \
    d ^= a;                         \
    d = ROTW8(d);                   \
    c += d;                         \
    b ^= c;                         \
    b = ROTW7(b);                   \
    b = ROTV3(b);                   \
    c = ROTV2(c);                   \
    d = ROTV1(d);

#define WRITE_XOR(in, op, d, v0, v1, v2, v3)           \
    STORE(op + d + 0, LOAD(in + d + 0) ^ REVV_BE(v0)); \
    STORE(op + d + 4, LOAD(in + d + 4) ^ REVV_BE(v1)); \
    STORE(op + d + 8, LOAD(in + d + 8) ^ REVV_BE(v2)); \
    STORE(op + d + 12, LOAD(in + d + 12) ^ REVV_BE(v3));

struct chacha_ctx {
    vec s1;
    vec s2;
    vec s3;
};

typedef struct chacha_ctx chacha_ctx;

static void
chacha_ivsetup(chacha_ctx *ctx, const uint8_t *iv, uint64_t ic)
{
    const vec s3 = {
        (uint32_t) ic,
        (uint32_t) (ic >> 32),
        ((const uint32_t *) (const void *) iv)[0],
        ((const uint32_t *) (const void *) iv)[1]
    };
    ctx->s3 = s3;
}

static void
chacha_ietf_ivsetup(chacha_ctx *ctx, const uint8_t *iv, uint32_t ic)
{
    const vec s3 = {
        ic,
        ((const uint32_t *) (const void *) iv)[0],
        ((const uint32_t *) (const void *) iv)[1],
        ((const uint32_t *) (const void *) iv)[2]
    };
    ctx->s3 = s3;
}

static void
chacha_keysetup(chacha_ctx *ctx, const uint8_t *k)
{
    ctx->s1 = LOAD(k);
    ctx->s2 = LOAD(k + 16);
}

static void
chacha_encrypt_bytes(chacha_ctx *ctx, const uint8_t *in, uint8_t *out,
                     unsigned long long inlen)
{
    CRYPTO_ALIGN(16) unsigned chacha_const[]
        = { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 };
    uint32_t           *op = (uint32_t *) (void *) out;
    const uint32_t     *ip = (const uint32_t *) (const void *) in;
    vec                 s0, s1, s2, s3;
    unsigned long long  iters;
    unsigned long long  i;

    if (inlen > 64ULL * (1ULL << 32) - 64ULL) {
        abort();
    }
    s0 = LOAD_ALIGNED(chacha_const);
    s1 = ctx->s1;
    s2 = ctx->s2;
    s3 = ctx->s3;

    for (iters = 0; iters < inlen / (BPI * 64); iters++) {
#if VBPI > 2
        vec v8, v9, v10, v11;
#endif
#if VBPI > 3
        vec v12, v13, v14, v15;
#endif
        vec v0, v1, v2, v3, v4, v5, v6, v7;
        v4 = v0 = s0;
        v5 = v1 = s1;
        v6 = v2 = s2;
        v3 = s3;
        v7 = v3 + ONE;
#if VBPI > 2
        v8 = v4;
        v9 = v5;
        v10 = v6;
        v11 = v7 + ONE;
#endif
#if VBPI > 3
        v12 = v8;
        v13 = v9;
        v14 = v10;
        v15 = v11 + ONE;
#endif
        for (i = CHACHA_RNDS / 2; i; i--) {
            DQROUND_VECTORS(v0, v1, v2, v3)
            DQROUND_VECTORS(v4, v5, v6, v7)
#if VBPI > 2
            DQROUND_VECTORS(v8, v9, v10, v11)
#endif
#if VBPI > 3
            DQROUND_VECTORS(v12, v13, v14, v15)
#endif
        }

        WRITE_XOR(ip, op, 0, v0 + s0, v1 + s1, v2 + s2, v3 + s3)
        s3 += ONE;
        WRITE_XOR(ip, op, 16, v4 + s0, v5 + s1, v6 + s2, v7 + s3)
        s3 += ONE;
#if VBPI > 2
        WRITE_XOR(ip, op, 32, v8 + s0, v9 + s1, v10 + s2, v11 + s3)
        s3 += ONE;
#endif
#if VBPI > 3
        WRITE_XOR(ip, op, 48, v12 + s0, v13 + s1, v14 + s2, v15 + s3)
        s3 += ONE;
#endif
        ip += VBPI * 16;
        op += VBPI * 16;
    }

    for (iters = inlen % (BPI * 64) / 64; iters != 0; iters--) {
        vec v0 = s0, v1 = s1, v2 = s2, v3 = s3;
        for (i = CHACHA_RNDS / 2; i; i--) {
            DQROUND_VECTORS(v0, v1, v2, v3);
        }
        WRITE_XOR(ip, op, 0, v0 + s0, v1 + s1, v2 + s2, v3 + s3)
        s3 += ONE;
        ip += 16;
        op += 16;
    }

    inlen = inlen % 64;
    if (inlen) {
        CRYPTO_ALIGN(16) vec buf[4];
        vec v0, v1, v2, v3;
        v0 = s0;
        v1 = s1;
        v2 = s2;
        v3 = s3;
        for (i = CHACHA_RNDS / 2; i; i--) {
            DQROUND_VECTORS(v0, v1, v2, v3);
        }

        if (inlen >= 16) {
            STORE(op + 0, LOAD(ip + 0) ^ REVV_BE(v0 + s0));
            if (inlen >= 32) {
                STORE(op + 4, LOAD(ip + 4) ^ REVV_BE(v1 + s1));
                if (inlen >= 48) {
                    STORE(op + 8, LOAD(ip + 8) ^ REVV_BE(v2 + s2));
                    buf[3] = REVV_BE(v3 + s3);
                } else {
                    buf[2] = REVV_BE(v2 + s2);
                }
            } else {
                buf[1] = REVV_BE(v1 + s1);
            }
        } else {
            buf[0] = REVV_BE(v0 + s0);
        }
        for (i = inlen & ~15ULL; i < inlen; i++) {
            ((char *) op)[i] = ((const char *) ip)[i] ^ ((char *) buf)[i];
        }
    }
}

static int
stream_vec(unsigned char *c, unsigned long long clen,
           const unsigned char *n, const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    (void) sizeof(int[crypto_stream_chacha20_KEYBYTES == 256 / 8 ? 1 : -1]);
    chacha_keysetup(&ctx, k);
    chacha_ivsetup(&ctx, n, 0ULL);
    memset(c, 0, clen);
    chacha_encrypt_bytes(&ctx, c, c, clen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
stream_ietf_vec(unsigned char *c, unsigned long long clen,
                const unsigned char *n, const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    (void) sizeof(int[crypto_stream_chacha20_KEYBYTES == 256 / 8 ? 1 : -1]);
    chacha_keysetup(&ctx, k);
    chacha_ietf_ivsetup(&ctx, n, 0ULL);
    memset(c, 0, clen);
    chacha_encrypt_bytes(&ctx, c, c, clen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
stream_vec_xor_ic(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen,
                  const unsigned char *n, uint64_t ic,
                  const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!mlen) {
        return 0;
    }
    chacha_keysetup(&ctx, k);
    chacha_ivsetup(&ctx, n, ic);
    chacha_encrypt_bytes(&ctx, m, c, mlen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
stream_ietf_vec_xor_ic(unsigned char *c, const unsigned char *m,
                       unsigned long long mlen,
                       const unsigned char *n, uint32_t ic,
                       const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!mlen) {
        return 0;
    }
    chacha_keysetup(&ctx, k);
    chacha_ietf_ivsetup(&ctx, n, ic);
    chacha_encrypt_bytes(&ctx, m, c, mlen);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

struct crypto_stream_chacha20_implementation
crypto_stream_chacha20_vec_implementation = {
    SODIUM_C99(.stream =) stream_vec,
    SODIUM_C99(.stream_ietf =) stream_ietf_vec,
    SODIUM_C99(.stream_xor_ic =) stream_vec_xor_ic,
    SODIUM_C99(.stream_ietf_xor_ic =) stream_ietf_vec_xor_ic
};

#endif
