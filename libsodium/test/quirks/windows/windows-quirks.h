
#include <stdlib.h>

#ifdef _WIN32

static void
srandom(unsigned seed)
{
    srand(seed);
}

static long
random(void)
{
    return (long) rand();
}

#endif
