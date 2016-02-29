#ifndef poly1305_sse2_H
#define poly1305_sse2_H

#include <stddef.h>

#include "crypto_onetimeauth_poly1305.h"

extern struct crypto_onetimeauth_poly1305_implementation
    crypto_onetimeauth_poly1305_sse2_implementation;

static int crypto_onetimeauth_poly1305_sse2(unsigned char *out,
                                            const unsigned char *in,
                                            unsigned long long inlen,
                                            const unsigned char *k);

static int crypto_onetimeauth_poly1305_sse2_verify(const unsigned char *h,
                                                   const unsigned char *in,
                                                   unsigned long long inlen,
                                                   const unsigned char *k);

static int crypto_onetimeauth_poly1305_sse2_init(crypto_onetimeauth_poly1305_state *state,
                                                 const unsigned char *key);

static int crypto_onetimeauth_poly1305_sse2_update(crypto_onetimeauth_poly1305_state *state,
                                                   const unsigned char *in,
                                                   unsigned long long inlen);

static int crypto_onetimeauth_poly1305_sse2_final(crypto_onetimeauth_poly1305_state *state,
                                                  unsigned char *out);

#endif /* poly1305_sse2_H */
