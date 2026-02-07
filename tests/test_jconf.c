#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "netutils.h"
#include "jconf.h"

static void
test_parse_addr_ipv4_with_port(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("192.168.1.1:8080", &addr);
    assert(addr.host != NULL);
    assert(addr.port != NULL);
    assert(strcmp(addr.host, "192.168.1.1") == 0);
    assert(strcmp(addr.port, "8080") == 0);
    free_addr(&addr);
}

static void
test_parse_addr_ipv6_with_port(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("[::1]:443", &addr);
    assert(addr.host != NULL);
    assert(addr.port != NULL);
    assert(strcmp(addr.host, "::1") == 0);
    assert(strcmp(addr.port, "443") == 0);
    free_addr(&addr);
}

static void
test_parse_addr_hostname_with_port(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("example.com:1234", &addr);
    assert(addr.host != NULL);
    assert(addr.port != NULL);
    assert(strcmp(addr.host, "example.com") == 0);
    assert(strcmp(addr.port, "1234") == 0);
    free_addr(&addr);
}

static void
test_parse_addr_no_port(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("10.0.0.1", &addr);
    assert(addr.host != NULL);
    assert(strcmp(addr.host, "10.0.0.1") == 0);
    /* Port may be NULL when no port is specified */
    free_addr(&addr);
}

static void
test_parse_addr_ipv6_no_port(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("::1", &addr);
    assert(addr.host != NULL);
    assert(strcmp(addr.host, "::1") == 0);
    free_addr(&addr);
}

int
main(void)
{
    test_parse_addr_ipv4_with_port();
    test_parse_addr_ipv6_with_port();
    test_parse_addr_hostname_with_port();
    test_parse_addr_no_port();
    test_parse_addr_ipv6_no_port();
    return 0;
}
