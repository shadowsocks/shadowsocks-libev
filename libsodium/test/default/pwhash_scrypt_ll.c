
#define TEST_NAME "pwhash_scrypt_ll"
#include "cmptest.h"

/* Tarsnap test vectors, see: https://www.tarsnap.com/scrypt/scrypt.pdf */

static const char *password1 = "";
static const char *salt1 = "";
static uint64_t N1 = 16U;
static uint32_t r1 = 1U;
static uint32_t p1 = 1U;

static const char *password2 = "password";
static const char *salt2 = "NaCl";
static uint64_t N2 = 1024U;
static uint32_t r2 = 8U;
static uint32_t p2 = 16U;

static const char *password3 = "pleaseletmein";
static const char *salt3 = "SodiumChloride";
static uint64_t N3 = 16384U;
static uint32_t r3 = 8U;
static uint32_t p3 = 1U;

static void test_vector(const char *password, const char *salt, uint64_t N,
                        uint32_t r, uint32_t p)
{
    uint8_t data[64];
    size_t i;
    size_t olen = (sizeof data / sizeof data[0]);
    size_t passwordLength = strlen(password);
    size_t saltLenght = strlen(salt);
    int lineitems = 0;
    int lineitemsLimit = 15;

    if (crypto_pwhash_scryptsalsa208sha256_ll(
            (const uint8_t *)password, passwordLength, (const uint8_t *)salt,
            saltLenght, N, r, p, data, olen) != 0) {
        printf("pwhash_scryptsalsa208sha256_ll([%s],[%s]) failure\n", password,
               salt);
        return;
    }

    printf("scrypt('%s', '%s', %llu, %lu, %lu, %lu) =\n", password, salt,
           (unsigned long long)N, (unsigned long)r, (unsigned long)p,
           (unsigned long)olen);

    for (i = 0; i < olen; ++i) {
        printf("%02x%c", data[i], lineitems < lineitemsLimit ? ' ' : '\n');
        lineitems = lineitems < lineitemsLimit ? lineitems + 1 : 0;
    }
}

int main(void)
{
    test_vector(password1, salt1, N1, r1, p1);
    test_vector(password2, salt2, N2, r2, p2);
    test_vector(password3, salt3, N3, r3, p3);

    return 0;
}
