
#define TEST_NAME "verify1"
#include "cmptest.h"

unsigned char v16[16], v16x[16];
unsigned char v32[32], v32x[32];
unsigned char v64[64], v64x[64];

int main(void)
{
    randombytes_buf(v16, sizeof v16);
    randombytes_buf(v32, sizeof v32);
    randombytes_buf(v64, sizeof v64);

    memcpy(v16x, v16, sizeof v16);
    memcpy(v32x, v32, sizeof v32);
    memcpy(v64x, v64, sizeof v64);

    printf("%d\n", crypto_verify_16(v16, v16x));
    printf("%d\n", crypto_verify_32(v32, v32x));
    printf("%d\n", crypto_verify_64(v64, v64x));

    v16x[randombytes_random() & 15U]++;
    v32x[randombytes_random() & 31U]++;
    v64x[randombytes_random() & 63U]++;

    printf("%d\n", crypto_verify_16(v16, v16x));
    printf("%d\n", crypto_verify_32(v32, v32x));
    printf("%d\n", crypto_verify_64(v64, v64x));

    assert(crypto_verify_16_bytes() == 16U);
    assert(crypto_verify_32_bytes() == 32U);
    assert(crypto_verify_64_bytes() == 64U);

    return 0;
}
