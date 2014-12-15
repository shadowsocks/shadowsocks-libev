
#include "crypto_sign.h"

size_t
crypto_sign_bytes(void)
{
    return crypto_sign_BYTES;
}

size_t
crypto_sign_seedbytes(void)
{
    return crypto_sign_SEEDBYTES;
}

size_t
crypto_sign_publickeybytes(void)
{
    return crypto_sign_PUBLICKEYBYTES;
}

size_t
crypto_sign_secretkeybytes(void)
{
    return crypto_sign_SECRETKEYBYTES;
}

const char *
crypto_sign_primitive(void)
{
    return crypto_sign_PRIMITIVE;
}

int
crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                         const unsigned char *seed)
{
    return crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    return crypto_sign_ed25519_keypair(pk, sk);
}

int
crypto_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk)
{
    return crypto_sign_ed25519(sm, smlen, m, mlen, sk);
}

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk)
{
    return crypto_sign_ed25519_open(m, mlen, sm, smlen, pk);
}

int
crypto_sign_detached(unsigned char *sig, unsigned long long *siglen,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *sk)
{
    return crypto_sign_ed25519_detached(sig, siglen, m, mlen, sk);
}

int
crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *pk)
{
    return crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}
