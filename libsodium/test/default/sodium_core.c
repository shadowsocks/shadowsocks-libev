
#define TEST_NAME "sodium_core"
#include "cmptest.h"

int main(void)
{
    printf("%d\n", sodium_init());

    (void)sodium_runtime_has_neon();
    (void)sodium_runtime_has_sse2();
    (void)sodium_runtime_has_sse3();

    return 0;
}
