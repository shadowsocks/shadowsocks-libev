
#define TEST_NAME "sodium_version"
#include "cmptest.h"

int main(void)
{
    printf("%d\n", sodium_version_string() != NULL);
    printf("%d\n", sodium_library_version_major() > 0);
    printf("%d\n", sodium_library_version_minor() >= 0);

    return 0;
}
