
#include <stddef.h>
#include <stdint.h>

#include "crypto_verify_64.h"

int
crypto_verify_64(const unsigned char *x, const unsigned char *y)
{
    uint_fast16_t d = 0U;
    int           i;

    for (i = 0; i < 64; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}
