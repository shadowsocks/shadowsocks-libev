/*
 * utils.c - Misc utilities
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#ifndef __MINGW32__
#include <pwd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils.h"

#ifdef HAVE_SETRLIMIT
#include <sys/time.h>
#include <sys/resource.h>
#endif

#define INT_DIGITS 19           /* enough for 64 bit integer */

#ifdef LIB_ONLY
FILE * logfile;
#endif

#ifdef HAS_SYSLOG
int use_syslog = 0;
#endif

#ifndef __MINGW32__
void ERROR(const char *s)
{
    char *msg = strerror(errno);
    LOGE("%s: %s", s, msg);

}
#endif

int use_tty = 1;

char *ss_itoa(int i)
{
    /* Room for INT_DIGITS digits, - and '\0' */
    static char buf[INT_DIGITS + 2];
    char *p = buf + INT_DIGITS + 1;     /* points to terminating '\0' */
    if (i >= 0) {
        do {
            *--p = '0' + (i % 10);
            i /= 10;
        } while (i != 0);
        return p;
    } else {                     /* i < 0 */
        do {
            *--p = '0' - (i % 10);
            i /= 10;
        } while (i != 0);
        *--p = '-';
    }
    return p;
}

/*
 * setuid() and setgid() for a specified user.
 */
int run_as(const char *user)
{
#ifndef __MINGW32__
    if (user[0]) {
#ifdef HAVE_GETPWNAM_R
        struct passwd pwdbuf, *pwd;
        size_t buflen;
        int err;

        for (buflen = 128;; buflen *= 2) {
            char buf[buflen];  /* variable length array */

            /* Note that we use getpwnam_r() instead of getpwnam(),
               which returns its result in a statically allocated buffer and
               cannot be considered thread safe. */
            err = getpwnam_r(user, &pwdbuf, buf, buflen, &pwd);
            if (err == 0 && pwd) {
                /* setgid first, because we may not be allowed to do it anymore after setuid */
                if (setgid(pwd->pw_gid) != 0) {
                    LOGE(
                        "Could not change group id to that of run_as user '%s': %s",
                        user, strerror(errno));
                    return 0;
                }

                if (setuid(pwd->pw_uid) != 0) {
                    LOGE(
                        "Could not change user id to that of run_as user '%s': %s",
                        user, strerror(errno));
                    return 0;
                }
                break;
            } else if (err != ERANGE) {
                if (err) {
                    LOGE("run_as user '%s' could not be found: %s", user, strerror(
                             err));
                } else {
                    LOGE("run_as user '%s' could not be found.", user);
                }
                return 0;
            } else if (buflen >= 16 * 1024) {
                /* If getpwnam_r() seems defective, call it quits rather than
                   keep on allocating ever larger buffers until we crash. */
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

        if (!(pwd = getpwnam(user))) {
            LOGE("run_as user %s could not be found.", user);
            return 0;
        }
        /* setgid first, because we may not allowed to do it anymore after setuid */
        if (setgid(pwd->pw_gid) != 0) {
            LOGE("Could not change group id to that of run_as user '%s': %s",
                 user, strerror(errno));
            return 0;
        }
        if (setuid(pwd->pw_uid) != 0) {
            LOGE("Could not change user id to that of run_as user '%s': %s",
                 user, strerror(errno));
            return 0;
        }
#endif
    }

#endif //__MINGW32__
    return 1;
}



char *ss_strndup(const char *s, size_t n)
{
    size_t len = strlen(s);
    char *ret;

    if (len <= n) {
        return strdup(s);
    }

    ret = malloc(n + 1);
    strncpy(ret, s, n);
    ret[n] = '\0';
    return ret;
}

void FATAL(const char *msg)
{
    LOGE("%s", msg);
    exit(-1);
}

void usage()
{
    printf("\n");
    printf("shadowsocks-libev %s\n\n", VERSION);
    printf(
        "  maintained by Max Lv <max.c.lv@gmail.com> and Linus Yang <laokongzi@gmail.com>\n\n");
    printf("  usage:\n\n");
    printf("    ss-[local|redir|server|tunnel]\n");
    printf("\n");
    printf(
        "       -s <server_host>           host name or ip address of your remote server\n");
    printf("\n");
    printf(
        "       -p <server_port>           port number of your remote server\n");
    printf("\n");
    printf(
        "       -l <local_port>            port number of your local server\n");
    printf("\n");
    printf(
        "       -k <password>              password of your remote server\n");
    printf("\n");
    printf(
        "       [-m <encrypt_method>]      encrypt method: table, rc4, rc4-md5,\n");
    printf(
        "                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,\n");
    printf(
        "                                  bf-cfb, camellia-128-cfb, camellia-192-cfb,\n");
    printf(
        "                                  camellia-256-cfb, cast5-cfb, des-cfb, idea-cfb,\n");
    printf(
        "                                  rc2-cfb, seed-cfb, salsa20 and chacha20\n");
    printf("\n");
    printf(
        "       [-f <pid_file>]            the file path to store pid\n");
    printf("\n");
    printf(
        "       [-t <timeout>]             socket timeout in seconds\n");
    printf("\n");
    printf(
        "       [-c <config_file>]         the path to config file\n");
    printf("\n");
    printf(
        "       [-i <interface>]           network interface to bind,\n");
    printf(
        "                                  not available in redir mode\n");
    printf("\n");
    printf(
        "       [-b <local_address>]       local address to bind,\n");
    printf(
        "                                  not available in server mode\n");
    printf("\n");
    printf(
        "       [-u]                       enable udprelay mode,\n");
    printf(
        "                                  not available in redir mode\n");
    printf("\n");
    printf(
        "       [-L <addr>:<port>]         specify destination server address and port\n");
    printf(
        "                                  for local port forwarding,\n");
    printf(
        "                                  only available in tunnel mode\n");
    printf("\n");
    printf(
        "       [-d <addr>]                setup name servers for internal DNS resolver,\n");
    printf(
        "                                  only available in server mode\n");
    printf("\n");
    printf(
        "       [--fast-open]              enable TCP fast open,\n");
    printf(
        "                                  only available in local and server mode,\n");
    printf(
        "                                  with Linux kernel > 3.7.0\n");
    printf("\n");
    printf(
        "       [--acl <acl_file>]         config file of ACL (Access Control List)\n");
    printf(
        "                                  only available in local and server mode\n");
    printf("\n");
    printf(
        "       [--bitcoin-list <bitcoin_file>]    config file of address list\n");
    printf(
        "                                          only available in server mode\n");
    printf("\n");
    printf(
        "       [--bitcoin-adddress <address>]     config file of bitcoin address\n");
    printf(
        "                                          only available in local mode\n");
    printf("\n");
    printf(
        "       [--bitcoin-privkey <private_key>]  config file of private key for above address\n");
    printf(
        "                                          only available in local mode\n");
    printf("\n");
    printf(
        "       [-v]                       verbose mode\n");
    printf("\n");
}

void daemonize(const char * path)
{
#ifndef __MINGW32__
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
        FILE *file = fopen(path, "w");
        if (file == NULL) {
            FATAL("Invalid pid file\n");
        }

        fprintf(file, "%d", pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif
}

#ifdef HAVE_SETRLIMIT
int set_nofile(int nofile)
{
    struct rlimit limit = { nofile, nofile }; /* set both soft and hard limit */

    if (nofile <= 0) {
        FATAL("nofile must be greater than 0\n");
    }

    if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
        if (errno == EPERM) {
            LOGE(
                "insufficient permission to change NOFILE, not starting as root?");
            return -1;
        } else if (errno == EINVAL) {
            LOGE("invalid nofile, decrease nofile and try again");
            return -1;
        } else {
            LOGE("setrlimit failed: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}
#endif

