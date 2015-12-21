
#include <stdint.h>

#include "crypto_stream_chacha20.h"

extern struct crypto_stream_chacha20_implementation
    crypto_stream_chacha20_ref_implementation;

int
crypto_stream_chacha20_ref(unsigned char *c, unsigned long long clen,
                           const unsigned char *n, const unsigned char *k);

int
crypto_stream_chacha20_ref_xor_ic(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n, uint64_t ic,
                                  const unsigned char *k);

int
crypto_stream_chacha20_ietf_ref(unsigned char *c, unsigned long long clen,
                                const unsigned char *n, const unsigned char *k);

int
crypto_stream_chacha20_ietf_ref_xor_ic(unsigned char *c, const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k);
