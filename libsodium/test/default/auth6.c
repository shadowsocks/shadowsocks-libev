
#define TEST_NAME "auth6"
#include "cmptest.h"

/* "Test Case 2" from RFC 4231 */
unsigned char key[32] = "Jefe";
unsigned char c[] = "what do ya want for nothing?";

unsigned char a[64];

int main(void)
{
    int i;

    crypto_auth_hmacsha512(a, c, sizeof c - 1U, key);
    for (i = 0; i < 64; ++i) {
        printf(",0x%02x", (unsigned int)a[i]);
        if (i % 8 == 7)
            printf("\n");
    }
    return 0;
}
