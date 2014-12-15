
#define TEST_NAME "secretbox_easy2"
#include "cmptest.h"

unsigned char m[10000];
unsigned char m2[10000];
unsigned char c[crypto_secretbox_MACBYTES + 10000];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char k[crypto_secretbox_KEYBYTES];
unsigned char mac[crypto_secretbox_MACBYTES];

int main(void)
{
    size_t mlen;
    size_t i;

    randombytes_buf(k, sizeof k);
    mlen = (size_t) randombytes_uniform((uint32_t) sizeof m);
    randombytes_buf(m, (unsigned long long) mlen);
    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(c, m, (unsigned long long) mlen, nonce, k);
    crypto_secretbox_open_easy(m2, c,
                               (unsigned long long) mlen + crypto_secretbox_MACBYTES,
                               nonce, k);
    printf("%d\n", memcmp(m, m2, mlen));

    for (i = 0; i < mlen + crypto_secretbox_MACBYTES - 1; i++) {
        if (crypto_secretbox_open_easy(m2, c, (unsigned long long) i,
                                       nonce, k) == 0) {
            printf("short open() should have failed\n");
            return 1;
        }
    }
    crypto_secretbox_detached(c, mac, m, (unsigned long long) mlen, nonce, k);
    if (crypto_secretbox_open_detached(m2, c, mac, (unsigned long long) mlen,
                                       nonce, k) != 0) {
        printf("crypto_secretbox_open_detached() failed\n");
    }
    printf("%d\n", memcmp(m, m2, mlen));

    memcpy(c, m, mlen);
    crypto_secretbox_easy(c, c, (unsigned long long) mlen, nonce, k);
    printf("%d\n", memcmp(m, c, mlen) == 0);
    printf("%d\n", memcmp(m, c + crypto_secretbox_MACBYTES, mlen) == 0);
    if (crypto_secretbox_open_easy(c, c,
                                   (unsigned long long) mlen + crypto_secretbox_MACBYTES,
                                   nonce, k) != 0) {
        printf("crypto_secretbox_open_easy() failed\n");
    }
    printf("%d\n", memcmp(m, c, mlen));

    return 0;
}
