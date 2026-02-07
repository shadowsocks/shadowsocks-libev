#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "utils.h"

static void
test_ss_itoa(void)
{
    char *s;

    s = ss_itoa(0);
    assert(s != NULL);
    assert(strcmp(s, "0") == 0);

    s = ss_itoa(42);
    assert(s != NULL);
    assert(strcmp(s, "42") == 0);

    s = ss_itoa(-1);
    assert(s != NULL);
    assert(strcmp(s, "-1") == 0);

    s = ss_itoa(12345);
    assert(s != NULL);
    assert(strcmp(s, "12345") == 0);
    (void)s;
}

static void
test_ss_isnumeric(void)
{
    assert(ss_isnumeric("12345") == 1);
    assert(ss_isnumeric("0") == 1);
    assert(ss_isnumeric("") == 0);
    assert(ss_isnumeric("abc") == 0);
    assert(ss_isnumeric("123abc") == 0);
    assert(ss_isnumeric("12.34") == 0);
}

static void
test_ss_strndup(void)
{
    char *s;

    s = ss_strndup("hello world", 5);
    assert(s != NULL);
    assert(strcmp(s, "hello") == 0);
    assert(strlen(s) == 5);
    free(s);

    s = ss_strndup("short", 10);
    assert(s != NULL);
    assert(strcmp(s, "short") == 0);
    free(s);

    s = ss_strndup("", 0);
    assert(s != NULL);
    assert(strcmp(s, "") == 0);
    free(s);
}

int
main(void)
{
    test_ss_itoa();
    test_ss_isnumeric();
    test_ss_strndup();
    return 0;
}
