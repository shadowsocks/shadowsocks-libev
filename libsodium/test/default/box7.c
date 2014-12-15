
#define TEST_NAME "box7"
#include "cmptest.h"

unsigned char alicesk[crypto_box_SECRETKEYBYTES];
unsigned char alicepk[crypto_box_PUBLICKEYBYTES];
unsigned char bobsk[crypto_box_SECRETKEYBYTES];
unsigned char bobpk[crypto_box_PUBLICKEYBYTES];
unsigned char n[crypto_box_NONCEBYTES];
unsigned char m[10000];
unsigned char c[10000];
unsigned char m2[10000];

int main(void)
{
    size_t mlen;
    size_t i;

    for (mlen = 0; mlen < 1000 && mlen + crypto_box_ZEROBYTES < sizeof m;
         ++mlen) {
        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        randombytes_buf(n, crypto_box_NONCEBYTES);
        randombytes_buf(m + crypto_box_ZEROBYTES, mlen);
        crypto_box(c, m, mlen + crypto_box_ZEROBYTES, n, bobpk, alicesk);
        if (crypto_box_open(m2, c, mlen + crypto_box_ZEROBYTES, n, alicepk,
                            bobsk) == 0) {
            for (i = 0; i < mlen + crypto_box_ZEROBYTES; ++i) {
                if (m2[i] != m[i]) {
                    printf("bad decryption\n");
                    break;
                }
            }
        } else {
            printf("ciphertext fails verification\n");
        }
    }
    return 0;
}
