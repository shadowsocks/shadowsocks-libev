
#define TEST_NAME "core3"
#include "cmptest.h"

unsigned char secondkey[32]
    = { 0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b,
        0x73, 0x38, 0x20, 0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb,
        0x61, 0xb9, 0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4 };

unsigned char noncesuffix[8]
    = { 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 };

unsigned char c[16] = { 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
                        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b };

unsigned char in[16] = { 0 };

unsigned char output[64 * 256 * 256];

unsigned char h[32];

int main(void)
{
    int i;
    long long pos = 0;

    for (i = 0; i < 8; ++i)
        in[i] = noncesuffix[i];
    do {
        do {
            crypto_core_salsa20(output + pos, in, secondkey, c);
            pos += 64;
        } while (++in[8]);
    } while (++in[9]);
    crypto_hash_sha256(h, output, sizeof output);
    for (i = 0; i < 32; ++i) {
        printf("%02x", h[i]);
    }
    printf("\n");
    assert(crypto_core_salsa20_outputbytes() > 0U);
    assert(crypto_core_salsa20_inputbytes() > 0U);
    assert(crypto_core_salsa20_keybytes() > 0U);
    assert(crypto_core_salsa20_constbytes() > 0U);

    return 0;
}
