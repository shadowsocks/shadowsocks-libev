#include "crypto_stream_chacha20.h"
#include "stream_chacha20.h"
#include "runtime.h"
#include "ref/stream_chacha20_ref.h"
#if (defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H) && defined(__GNUC__))
# include "vec/stream_chacha20_vec.h"
#endif

static const crypto_stream_chacha20_implementation *implementation =
    &crypto_stream_chacha20_ref_implementation;

size_t
crypto_stream_chacha20_keybytes(void) {
    return crypto_stream_chacha20_KEYBYTES;
}

size_t
crypto_stream_chacha20_noncebytes(void) {
    return crypto_stream_chacha20_NONCEBYTES;
}

size_t
crypto_stream_chacha20_ietf_noncebytes(void) {
    return crypto_stream_chacha20_IETF_NONCEBYTES;
}

int
crypto_stream_chacha20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k)
{
    return implementation->stream(c, clen, n, k);
}

int
crypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
{
    return implementation->stream_ietf(c, clen, n, k);
}

int
crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n, uint64_t ic,
                              const unsigned char *k)
{
    return implementation->stream_xor_ic(c, m, mlen, n, ic, k);
}

int
crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *n, uint32_t ic,
                                   const unsigned char *k)
{
    return implementation->stream_ietf_xor_ic(c, m, mlen, n, ic, k);
}

int
crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k)
{
    return implementation->stream_xor_ic(c, m, mlen, n, 0U, k);
}

int
crypto_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *n,
                                const unsigned char *k)
{
    return implementation->stream_ietf_xor_ic(c, m, mlen, n, 0U, k);
}

int
_crypto_stream_chacha20_pick_best_implementation(void)
{
    implementation = &crypto_stream_chacha20_ref_implementation;
#if (defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H) && defined(__GNUC__))
    if (sodium_runtime_has_ssse3()) {
        implementation = &crypto_stream_chacha20_vec_implementation;
    }
#endif
    return 0;
}
