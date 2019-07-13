/*
 * utils.c - Misc utilities
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifndef __MINGW32__
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#else
#include <malloc.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sodium.h>

#include "crypto.h"
#include "utils.h"

#ifdef HAVE_SETRLIMIT
#include <sys/time.h>
#include <sys/resource.h>
#endif

#define INT_DIGITS 19 /* enough for 64 bit integer */

int use_tty = 0;
int use_syslog = 0;
FILE *logfile = NULL;

char *
ss_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1; /* points to terminating '\0' */
    if (i >= 0)
    {
        do
        {
            *--p = '0' + (i % 10);
            i /= 10;
        } while (i != 0);
        return p;
    }
    else
    { /* i < 0 */
        do
        {
            *--p = '0' - (i % 10);
            i /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

int ss_isnumeric(const char *s)
{
    if (!s || !*s)
        return 0;
    while (isdigit((unsigned char)*s))
        ++s;
    return *s == '\0';
}

/*
 * setuid() and setgid() for a specified user.
 */
int run_as(const char *user)
{
#ifndef __MINGW32__
    if (user[0])
    {
        /* Convert user to a long integer if it is a non-negative number.
         * -1 means it is a user name. */
        long uid = -1;
        if (ss_isnumeric(user))
        {
            errno = 0;
            char *endptr;
            uid = strtol(user, &endptr, 10);
            if (errno || endptr == user)
                uid = -1;
        }

#ifdef HAVE_GETPWNAM_R
        struct passwd pwdbuf, *pwd;
        memset(&pwdbuf, 0, sizeof(struct passwd));
        size_t buflen;
        int err;

        for (buflen = 128;; buflen *= 2)
        {
            char buf[buflen]; /* variable length array */

            /* Note that we use getpwnam_r() instead of getpwnam(),
             * which returns its result in a statically allocated buffer and
             * cannot be considered thread safe. */
            err = uid >= 0 ? getpwuid_r((uid_t)uid, &pwdbuf, buf, buflen, &pwd)
                           : getpwnam_r(user, &pwdbuf, buf, buflen, &pwd);

            if (err == 0 && pwd)
            {
                /* setgid first, because we may not be allowed to do it anymore after setuid */
                if (setgid(pwd->pw_gid) != 0)
                {
                    LOGE(
                        "Could not change group id to that of run_as user '%s': %s",
                        pwd->pw_name, strerror(errno));
                    return 0;
                }

#ifndef __CYGWIN__
                if (initgroups(pwd->pw_name, pwd->pw_gid) == -1)
                {
                    LOGE("Could not change supplementary groups for user '%s'.", pwd->pw_name);
                    return 0;
                }
#endif

                if (setuid(pwd->pw_uid) != 0)
                {
                    LOGE(
                        "Could not change user id to that of run_as user '%s': %s",
                        pwd->pw_name, strerror(errno));
                    return 0;
                }
                break;
            }
            else if (err != ERANGE)
            {
                if (err)
                {
                    LOGE("run_as user '%s' could not be found: %s", user,
                         strerror(err));
                }
                else
                {
                    LOGE("run_as user '%s' could not be found.", user);
                }
                return 0;
            }
            else if (buflen >= 16 * 1024)
            {
                /* If getpwnam_r() seems defective, call it quits rather than
                 * keep on allocating ever larger buffers until we crash. */
                LOGE(
                    "getpwnam_r() requires more than %u bytes of buffer space.",
                    (unsigned)buflen);
                return 0;
            }
            /* Else try again with larger buffer. */
        }
#else
        /* No getpwnam_r() :-(  We'll use getpwnam() and hope for the best. */
        struct passwd *pwd;

        if (!(pwd = uid >= 0 ? getpwuid((uid_t)uid) : getpwnam(user)))
        {
            LOGE("run_as user %s could not be found.", user);
            return 0;
        }
        /* setgid first, because we may not allowed to do it anymore after setuid */
        if (setgid(pwd->pw_gid) != 0)
        {
            LOGE("Could not change group id to that of run_as user '%s': %s",
                 pwd->pw_name, strerror(errno));
            return 0;
        }
        if (initgroups(pwd->pw_name, pwd->pw_gid) == -1)
        {
            LOGE("Could not change supplementary groups for user '%s'.", pwd->pw_name);
            return 0;
        }
        if (setuid(pwd->pw_uid) != 0)
        {
            LOGE("Could not change user id to that of run_as user '%s': %s",
                 pwd->pw_name, strerror(errno));
            return 0;
        }
#endif
    }
#else
    LOGE("run_as(): not implemented in MinGW port");
#endif

    return 1;
}

char *
ss_strndup(const char *s, size_t n)
{
    size_t len = strlen(s);
    char *ret;

    if (len <= n)
    {
        return strdup(s);
    }

    ret = ss_malloc(n + 1);
    strncpy(ret, s, n);
    ret[n] = '\0';
    return ret;
}

int ss_is_ipv6addr(const char *addr)
{
    return strcmp(addr, ":") > 0;
}

char *
trim_whitespace(char *str)
{
    if (str == NULL)
        return str;

    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0) // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

void usage()
{
    printf("\n");
    printf("shadowsocks-libev %s\n\n", VERSION);
    printf(
        "  maintained by Max Lv <max.c.lv@gmail.com> and Linus Yang <laokongzi@gmail.com>\n\n");
    printf("  usage:\n\n");
#ifdef MODULE_LOCAL
    printf("    ss-local\n");
#elif MODULE_REMOTE
    printf("    ss-server\n");
#elif MODULE_TUNNEL
    printf("    ss-tunnel\n");
#elif MODULE_REDIR
    printf("    ss-redir\n");
#elif MODULE_MANAGER
    printf("    ss-manager\n");
#endif
    printf("\n");
    printf(
        "       -s <server_host>           Host name or IP address of your remote server.\n");
    printf(
        "       -p <server_port>           Port number of your remote server.\n");
    printf(
        "       -l <local_port>            Port number of your local server.\n");
    printf(
        "       -k <password>              Password of your remote server.\n");
    printf(
        "       -m <encrypt_method>        Encrypt method: rc4-md5, \n");
    printf(
        "                                  aes-128-gcm, aes-192-gcm, aes-256-gcm,\n");
    printf(
        "                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,\n");
    printf(
        "                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,\n");
    printf(
        "                                  camellia-128-cfb, camellia-192-cfb,\n");
    printf(
        "                                  camellia-256-cfb, bf-cfb,\n");
    printf(
        "                                  chacha20-ietf-poly1305,\n");
#ifdef FS_HAVE_XCHACHA20IETF
    printf(
        "                                  xchacha20-ietf-poly1305,\n");
#endif
    printf(
        "                                  salsa20, chacha20 and chacha20-ietf.\n");
    printf(
        "                                  The default cipher is chacha20-ietf-poly1305.\n");
    printf("\n");
    printf(
        "       [-a <user>]                Run as another user.\n");
    printf(
        "       [-f <pid_file>]            The file path to store pid.\n");
    printf(
        "       [-t <timeout>]             Socket timeout in seconds.\n");
    printf(
        "       [-c <config_file>]         The path to config file.\n");
#ifdef HAVE_SETRLIMIT
    printf(
        "       [-n <number>]              Max number of open files.\n");
#endif
#ifndef MODULE_REDIR
    printf(
        "       [-i <interface>]           Network interface to bind.\n");
#endif
    printf(
        "       [-b <local_address>]       Local address to bind.\n");
    printf("\n");
    printf(
        "       [-u]                       Enable UDP relay.\n");
#ifdef MODULE_REDIR
    printf(
        "                                  TPROXY is required in redir mode.\n");
#endif
    printf(
        "       [-U]                       Enable UDP relay and disable TCP relay.\n");
#ifdef MODULE_REMOTE
    printf(
        "       [-6]                       Resovle hostname to IPv6 address first.\n");
#endif
    printf("\n");
#ifdef MODULE_TUNNEL
    printf(
        "       [-L <addr>:<port>]         Destination server address and port\n");
    printf(
        "                                  for local port forwarding.\n");
#endif
#ifdef MODULE_REMOTE
    printf(
        "       [-d <addr>]                Name servers for internal DNS resolver.\n");
#endif
    printf(
        "       [--reuse-port]             Enable port reuse.\n");
#if defined(MODULE_REMOTE) || defined(MODULE_LOCAL) || defined(MODULE_REDIR)
    printf(
        "       [--fast-open]              Enable TCP fast open.\n");
    printf(
        "                                  with Linux kernel > 3.7.0.\n");
#endif
#if defined(MODULE_REMOTE) || defined(MODULE_LOCAL)
    printf(
        "       [--acl <acl_file>]         Path to ACL (Access Control List).\n");
#endif
#if defined(MODULE_REMOTE) || defined(MODULE_MANAGER)
    printf(
        "       [--manager-address <addr>] UNIX domain socket address.\n");
#endif
#ifdef MODULE_MANAGER
    printf(
        "       [--executable <path>]      Path to the executable of ss-server.\n");
    printf(
        "       [-D <path>]                Path to the working directory of ss-manager.\n");
#endif
    printf(
        "       [--mtu <MTU>]              MTU of your network interface.\n");
#ifdef __linux__
    printf(
        "       [--mptcp]                  Enable Multipath TCP on MPTCP Kernel.\n");
#endif
#ifndef MODULE_MANAGER
    printf(
        "       [--no-delay]               Enable TCP_NODELAY.\n");
    printf(
        "       [--key <key_in_base64>]    Key of your remote server.\n");
#endif
    printf(
        "       [--plugin <name>]          Enable SIP003 plugin. (Experimental)\n");
    printf(
        "       [--plugin-opts <options>]  Set SIP003 plugin options. (Experimental)\n");
    printf("\n");
    printf(
        "       [-v]                       Verbose mode.\n");
    printf(
        "       [-h, --help]               Print this message.\n");
    printf("\n");
}

void daemonize(const char *path)
{
#ifndef __MINGW32__
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
     * we can exit the parent process. */
    if (pid > 0)
    {
        FILE *file = fopen(path, "w");
        if (file == NULL)
        {
            FATAL("Invalid pid file\n");
        }

        fprintf(file, "%d", (int)pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
    {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0)
    {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null)
    {
        /* Redirect to null device  */
        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
    }
    else
    {
        /* Close the standard file descriptors */
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    /* Close the standard file descriptors */
    close(STDIN_FILENO);
#else
    LOGE("daemonize(): not implemented in MinGW port");
#endif
}

#ifdef HAVE_SETRLIMIT
int set_nofile(int nofile)
{
    struct rlimit limit = {nofile, nofile}; /* set both soft and hard limit */

    if (nofile <= 0)
    {
        FATAL("nofile must be greater than 0\n");
    }

    if (setrlimit(RLIMIT_NOFILE, &limit) < 0)
    {
        if (errno == EPERM)
        {
            LOGE(
                "insufficient permission to change NOFILE, not starting as root?");
            return -1;
        }
        else if (errno == EINVAL)
        {
            LOGE("invalid nofile, decrease nofile and try again");
            return -1;
        }
        else
        {
            LOGE("setrlimit failed: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

#endif

size_t
readoff_from(char **content, const char *file)
{
    FILE *f = strcmp(file, "-") == 0 ? stdin : fopen(file, "r");
    if (f == NULL)
    {
        FATAL("Invalid file path %s", file);
    }

    size_t pos = 0;
    char buf[1024] = { 0 };

    while (fgets(buf, sizeof(buf), f))
    {
        size_t len = strlen(buf);
        *content = ss_realloc(*content, pos + len);
        strncpy(*content + pos, buf, len);
        pos += len;
    }

    if (ferror(f))
    {
        FATAL("Failed to read the file.")
    }

    fclose(f);

    return pos;
}

char *
get_default_conf(void)
{
#ifndef __MINGW32__
    static char sysconf[] = "/etc/shadowsocks-libev/config.json";
    static char *userconf = NULL;
    static int buf_size = 0;
    char *conf_home;

    conf_home = getenv("XDG_CONFIG_HOME");

    // Memory of userconf only gets allocated once, and will not be
    // freed. It is used as static buffer.
    if (!conf_home)
    {
        if (buf_size == 0)
        {
            buf_size = 50 + strlen(getenv("HOME"));
            userconf = malloc(buf_size);
        }
        snprintf(userconf, buf_size, "%s%s", getenv("HOME"),
                 "/.config/shadowsocks-libev/config.json");
    }
    else
    {
        if (buf_size == 0)
        {
            buf_size = 50 + strlen(conf_home);
            userconf = malloc(buf_size);
        }
        snprintf(userconf, buf_size, "%s%s", conf_home,
                 "/shadowsocks-libev/config.json");
    }

    // Check if the user-specific config exists.
    if (access(userconf, F_OK) != -1)
        return userconf;

    // If not, fall back to the system-wide config.
    return sysconf;
#else
    return "config.json";
#endif
}

/**
 * strtotime
 * ---------------------
 * Convert a string to a time value in seconds.
 * written by Thomas Moestl.
   rewritten in C from scratch by Paul A. Rombouts
 *
 */
time_t
strtotime(char *str)
{
    time_t retval = 0, t;
    char c;

    while (isalnum(c = *str))
    {
        if (!isdigit(c))
            break;

        t = strtol(str, &str, 10);

        struct { char c; time_t t; } tmtable[] = {
            { 's',  1 }, { 'm', 60 }, { 'h', 60 },
            { 'd', 24 }, { 'w',  7 }
        };

        if (isalpha(c = *str))
        {
            for (int i = 0; i < nelem(tmtable) && tmtable[i++].c != c;) {
                t *= tmtable[i].t;
            }
            ++str;
        }

        retval += t;
    }

    return retval;
}
