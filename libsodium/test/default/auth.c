
#define TEST_NAME "auth"
#include "cmptest.h"

/* "Test Case 2" from RFC 4231 */
unsigned char key[32] = "Jefe";
unsigned char c[] = "what do ya want for nothing?";

/* Hacker manifesto */
unsigned char key2[] = "Another one got caught today, it's all over the papers. \"Teenager Arrested in Computer Crime Scandal\", \"Hacker Arrested after Bank Tampering\"... Damn kids. They're all alike.";

unsigned char a[crypto_auth_BYTES];
unsigned char a2[crypto_auth_hmacsha512_BYTES];

int main(void)
{
    crypto_auth_hmacsha512_state st;
    int i;

    crypto_auth(a, c, sizeof c - 1U, key);
    for (i = 0; i < sizeof a; ++i) {
        printf(",0x%02x", (unsigned int)a[i]);
        if (i % 8 == 7)
            printf("\n");
    }
    printf("\n");

    crypto_auth_hmacsha512_init(&st, key, sizeof key);
    crypto_auth_hmacsha512_update(&st, c, 1U);
    crypto_auth_hmacsha512_update(&st, c, sizeof c - 2U);
    crypto_auth_hmacsha512_final(&st, a2);
    for (i = 0; i < sizeof a2; ++i) {
        printf(",0x%02x", (unsigned int)a2[i]);
        if (i % 8 == 7)
            printf("\n");
    }
    printf("\n");

    crypto_auth_hmacsha512_init(&st, key2, sizeof key2);
    crypto_auth_hmacsha512_update(&st, c, 1U);
    crypto_auth_hmacsha512_update(&st, c, sizeof c - 2U);
    crypto_auth_hmacsha512_final(&st, a2);
    for (i = 0; i < sizeof a2; ++i) {
        printf(",0x%02x", (unsigned int)a2[i]);
        if (i % 8 == 7)
            printf("\n");
    }

    assert(crypto_auth_bytes() > 0U);
    assert(crypto_auth_keybytes() > 0U);
    assert(strcmp(crypto_auth_primitive(), "hmacsha512256") == 0);
    assert(crypto_auth_hmacsha256_bytes() > 0U);
    assert(crypto_auth_hmacsha256_keybytes() > 0U);
    assert(crypto_auth_hmacsha512_bytes() > 0U);
    assert(crypto_auth_hmacsha512_keybytes() > 0U);
    assert(crypto_auth_hmacsha512256_bytes() == crypto_auth_bytes());
    assert(crypto_auth_hmacsha512256_keybytes() == crypto_auth_keybytes());

    return 0;
}
