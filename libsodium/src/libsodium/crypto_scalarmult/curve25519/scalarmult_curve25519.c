
#include "crypto_scalarmult_curve25519.h"
#include "scalarmult_curve25519.h"
#include "runtime.h"

#ifdef HAVE_AVX_ASM
# include "sandy2x/curve25519_sandy2x.h"
#endif
#ifdef HAVE_TI_MODE
# include "donna_c64/curve25519_donna_c64.h"
static const crypto_scalarmult_curve25519_implementation *implementation =
    &crypto_scalarmult_curve25519_donna_c64_implementation;
#else
# include "ref10/curve25519_ref10.h"
static const crypto_scalarmult_curve25519_implementation *implementation =
    &crypto_scalarmult_curve25519_ref10_implementation;
#endif

int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    size_t        i;
    unsigned char d = 0;

    if (implementation->mult(q, n, p) != 0) {
        return -1;
    }
    for (i = 0; i < crypto_scalarmult_curve25519_BYTES; i++) {
        d |= q[i];
    }
    return -(1 & ((d - 1) >> 8));
}

int
crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    return implementation->mult_base(q, n);
}

size_t
crypto_scalarmult_curve25519_bytes(void)
{
    return crypto_scalarmult_curve25519_BYTES;
}

size_t
crypto_scalarmult_curve25519_scalarbytes(void)
{
    return crypto_scalarmult_curve25519_SCALARBYTES;
}

int
_crypto_scalarmult_curve25519_pick_best_implementation(void)
{
#ifdef HAVE_TI_MODE
    implementation = &crypto_scalarmult_curve25519_donna_c64_implementation;
#else
    implementation = &crypto_scalarmult_curve25519_ref10_implementation;
#endif
#ifdef HAVE_AVX_ASM
    if (sodium_runtime_has_avx()) {
        implementation = &crypto_scalarmult_curve25519_sandy2x_implementation;
    }
#endif
    return 0;
}
