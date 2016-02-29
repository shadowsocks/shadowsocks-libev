#ifndef poly1305_donna_H
#define poly1305_donna_H

#include <stddef.h>

#include "crypto_onetimeauth_poly1305.h"

extern struct crypto_onetimeauth_poly1305_implementation
    crypto_onetimeauth_poly1305_donna_implementation;

static int crypto_onetimeauth_poly1305_donna(unsigned char *out,
                                             const unsigned char *in,
                                             unsigned long long inlen,
                                             const unsigned char *k);

static int crypto_onetimeauth_poly1305_donna_verify(const unsigned char *h,
                                                    const unsigned char *in,
                                                    unsigned long long inlen,
                                                    const unsigned char *k);

static int crypto_onetimeauth_poly1305_donna_init(crypto_onetimeauth_poly1305_state *state,
                                                  const unsigned char *key);

static int crypto_onetimeauth_poly1305_donna_update(crypto_onetimeauth_poly1305_state *state,
                                                    const unsigned char *in,
                                                    unsigned long long inlen);

static int crypto_onetimeauth_poly1305_donna_final(crypto_onetimeauth_poly1305_state *state,
                                                   unsigned char *out);

#endif /* poly1305_donna_H */
