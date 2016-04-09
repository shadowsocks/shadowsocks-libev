
#ifndef onetimeauth_poly1305_H
#define onetimeauth_poly1305_H

typedef struct crypto_onetimeauth_poly1305_implementation {
    int (*onetimeauth)(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen,
                       const unsigned char *k);
    int (*onetimeauth_verify)(const unsigned char *h,
                              const unsigned char *in,
                              unsigned long long inlen,
                              const unsigned char *k);
    int (*onetimeauth_init)(crypto_onetimeauth_poly1305_state *state,
                            const unsigned char *key);
    int (*onetimeauth_update)(crypto_onetimeauth_poly1305_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);
    int (*onetimeauth_final)(crypto_onetimeauth_poly1305_state *state,
                             unsigned char *out);
} crypto_onetimeauth_poly1305_implementation;

#endif
