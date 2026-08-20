/*
 * Configure-time check that the mbedTLS headers and the linked library are
 * the same version. A mismatch is not a link error, but struct layouts
 * differ across major versions, so contexts sized with sizeof() from the
 * headers are overrun by library code that expects the other layout.
 *
 * Exits 0 when the compile-time and runtime versions agree.
 */

#include <stdio.h>
#include <string.h>

#include <mbedtls/version.h>

int
main(void)
{
    char runtime[32] = { 0 };

    mbedtls_version_get_string(runtime);

    if (strcmp(runtime, MBEDTLS_VERSION_STRING) != 0) {
        printf("headers say %s, library reports %s",
               MBEDTLS_VERSION_STRING, runtime);
        return 1;
    }

    return 0;
}
