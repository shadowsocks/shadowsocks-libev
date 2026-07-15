#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

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

static void
test_parse_addr_malformed_bracketed_ipv6_is_not_rewritten(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("[::1", &addr);
    assert(addr.host != NULL);
    assert(addr.port == NULL);
    assert(strcmp(addr.host, "[::1") == 0);
    free_addr(&addr);
}

static void
test_parse_addr_invalid_ipv6_like_host_is_not_rewritten(void)
{
    ss_addr_t addr;
    memset(&addr, 0, sizeof(addr));
    parse_addr("bad::host", &addr);
    assert(addr.host != NULL);
    assert(addr.port == NULL);
    assert(strcmp(addr.host, "bad::host") == 0);
    free_addr(&addr);
}

static void
test_read_jconf_preserves_64bit_integer_strings(void)
{
    char path[] = "/tmp/ss_jconf_test.XXXXXX";
    int fd      = mkstemp(path);
    assert(fd >= 0);

    FILE *f = fdopen(fd, "w");
    assert(f != NULL);
    fprintf(f, "{\n");
    fprintf(f, "\"server\":\"127.0.0.1\",\n");
    fprintf(f, "\"server_port\":4294967296,\n");
    fprintf(f, "\"password\":\"password\",\n");
    fprintf(f, "\"method\":\"aes-128-gcm\"\n");
    fprintf(f, "}\n");
    fclose(f);

    jconf_t *conf = read_jconf(path);
    assert(conf != NULL);
    assert(conf->remote_port != NULL);
    assert(strcmp(conf->remote_port, "4294967296") == 0);

    unlink(path);
}

static void
write_minimal_config(FILE *f, const char *extra_line)
{
    fprintf(f, "{\n");
    fprintf(f, "\"server\":\"127.0.0.1\",\n");
    fprintf(f, "\"server_port\":8388,\n");
    fprintf(f, "\"password\":\"password\",\n");
    fprintf(f, "\"method\":\"aes-128-gcm\"");
    if (extra_line != NULL) {
        fprintf(f, ",\n%s", extra_line);
    }
    fprintf(f, "\n}\n");
}

#ifndef __MINGW32__
static void
test_read_jconf_rejects_out_of_range_int_options(void)
{
    char path[] = "/tmp/ss_jconf_test.XXXXXX";
    int fd      = mkstemp(path);
    assert(fd >= 0);

    FILE *f = fdopen(fd, "w");
    assert(f != NULL);
    write_minimal_config(f, "\"tcp_incoming_sndbuf\":2147483648");
    fclose(f);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        read_jconf(path);
        _exit(0);
    }

    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) != 0);

    unlink(path);
}
#endif

int
main(void)
{
    test_parse_addr_ipv4_with_port();
    test_parse_addr_ipv6_with_port();
    test_parse_addr_hostname_with_port();
    test_parse_addr_no_port();
    test_parse_addr_ipv6_no_port();
    test_parse_addr_malformed_bracketed_ipv6_is_not_rewritten();
    test_parse_addr_invalid_ipv6_like_host_is_not_rewritten();
    test_read_jconf_preserves_64bit_integer_strings();
#ifndef __MINGW32__
    test_read_jconf_rejects_out_of_range_int_options();
#endif
    return 0;
}
