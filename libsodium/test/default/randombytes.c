
#define TEST_NAME "randombytes"
#include "cmptest.h"

unsigned char x[65536];
unsigned long long freq[256];

static int compat_tests(void)
{
    size_t i;

    memset(x, 0, sizeof x);
    randombytes(x, sizeof x);
    for (i = 0; i < 256; ++i) {
        freq[i] = 0;
    }
    for (i = 0; i < sizeof x; ++i) {
        ++freq[255 & (int)x[i]];
    }
    for (i = 0; i < 256; ++i) {
        if (!freq[i]) {
            printf("nacl_tests failed\n");
        }
    }
    return 0;
}

static int randombytes_tests(void)
{
    unsigned int i;

    assert(strcmp(randombytes_implementation_name(), "sysrandom") == 0);

    randombytes(x, 1U);
    randombytes_close();

    for (i = 0; i < 256; ++i) {
        freq[i] = 0;
    }
    for (i = 0; i < 65536; ++i) {
        ++freq[randombytes_uniform(256)];
    }
    for (i = 0; i < 256; ++i) {
        if (!freq[i]) {
            printf("randombytes_uniform() test failed\n");
        }
    }
    assert(randombytes_uniform(1U) == 0U);
    randombytes_close();
    randombytes_set_implementation(&randombytes_salsa20_implementation);
    assert(strcmp(randombytes_implementation_name(), "salsa20") == 0);
    randombytes_stir();
    for (i = 0; i < 256; ++i) {
        freq[i] = 0;
    }
    for (i = 0; i < 65536; ++i) {
        ++freq[randombytes_uniform(256)];
    }
    for (i = 0; i < 256; ++i) {
        if (!freq[i]) {
            printf("randombytes_uniform() test failed\n");
        }
    }
    memset(x, 0, sizeof x);
    randombytes_buf(x, sizeof x);
    for (i = 0; i < 256; ++i) {
        freq[i] = 0;
    }
    for (i = 0; i < sizeof x; ++i) {
        ++freq[255 & (int)x[i]];
    }
    for (i = 0; i < 256; ++i) {
        if (!freq[i]) {
            printf("randombytes_buf() test failed\n");
        }
    }
    assert(randombytes_uniform(1U) == 0U);
    randombytes_close();

    randombytes(x, 1U);
    randombytes_close();

    return 0;
}

int main(void)
{
    compat_tests();
    randombytes_tests();
    printf("OK\n");

    return 0;
}
