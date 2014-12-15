
#define TEST_NAME "scalarmult"
#include "cmptest.h"

unsigned char alicesk[32]
    = { 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
        0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
        0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a };

unsigned char alicepk[32];

int main(void)
{
    int i;

    crypto_scalarmult_base(alicepk, alicesk);

    for (i = 0; i < 32; ++i) {
        if (i > 0) {
            printf(",");
        } else {
            printf(" ");
        }
        printf("0x%02x", (unsigned int)alicepk[i]);
        if (i % 8 == 7) {
            printf("\n");
        }
    }
    assert(crypto_scalarmult_bytes() > 0U);
    assert(crypto_scalarmult_scalarbytes() > 0U);
    assert(strcmp(crypto_scalarmult_primitive(), "curve25519") == 0);
    assert(crypto_scalarmult_bytes() == crypto_scalarmult_curve25519_bytes());
    assert(crypto_scalarmult_scalarbytes()
           == crypto_scalarmult_curve25519_scalarbytes());
    assert(crypto_scalarmult_bytes() == crypto_scalarmult_scalarbytes());

    return 0;
}
