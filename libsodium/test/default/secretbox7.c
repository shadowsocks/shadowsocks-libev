
#define TEST_NAME "secretbox7"
#include "cmptest.h"

unsigned char k[crypto_secretbox_KEYBYTES];
unsigned char n[crypto_secretbox_NONCEBYTES];
unsigned char m[10000];
unsigned char c[10000];
unsigned char m2[10000];

int main(void)
{
    size_t mlen;
    size_t i;

    for (mlen = 0; mlen < 1000 && mlen + crypto_secretbox_ZEROBYTES < sizeof m;
         ++mlen) {
        randombytes_buf(k, crypto_secretbox_KEYBYTES);
        randombytes_buf(n, crypto_secretbox_NONCEBYTES);
        randombytes_buf(m + crypto_secretbox_ZEROBYTES, mlen);
        crypto_secretbox(c, m, mlen + crypto_secretbox_ZEROBYTES, n, k);
        if (crypto_secretbox_open(m2, c, mlen + crypto_secretbox_ZEROBYTES, n,
                                  k) == 0) {
            for (i = 0; i < mlen + crypto_secretbox_ZEROBYTES; ++i) {
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
