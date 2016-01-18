/*
 * netutils.c - Network utilities
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

#include <math.h>

#include <libcork/core.h>
#include <udns.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __MINGW32__
#include "win32.h"
#define sleep(n) Sleep(1000 * (n))
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include "netutils.h"
#include "utils.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

int set_reuseport(int socket)
{
    int opt = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

size_t get_sockaddr_len(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

size_t get_sockaddr(char *host, char *port, struct sockaddr_storage *storage, int block)
{
    struct cork_ip ip;
    if (cork_ip_init(&ip, host) != -1) {
        if (ip.version == 4) {
            struct sockaddr_in *addr = (struct sockaddr_in *)storage;
            addr->sin_family = AF_INET;
            dns_pton(AF_INET, host, &(addr->sin_addr));
            if (port != NULL) {
                addr->sin_port = htons(atoi(port));
            }
        } else if (ip.version == 6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
            addr->sin6_family = AF_INET6;
            dns_pton(AF_INET6, host, &(addr->sin6_addr));
            if (port != NULL) {
                addr->sin6_port = htons(atoi(port));
            }
        }
        return 0;
    } else {
        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
        hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

        int err, i;

        for (i = 1; i < 8; i++) {
            err = getaddrinfo(host, port, &hints, &result);
            if (!block || !err) {
                break;
            } else {
                sleep(pow(2, i));
                LOGE("failed to resolve server name, wait %.0f seconds", pow(2, i));
            }
        }

        if (err != 0) {
            LOGE("getaddrinfo: %s", gai_strerror(err));
            return -1;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next)
            if (rp->ai_family == AF_INET) {
                memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in));
                break;
            }

        if (rp == NULL) {
            for (rp = result; rp != NULL; rp = rp->ai_next)
                if (rp->ai_family == AF_INET6) {
                    memcpy(storage, rp->ai_addr, sizeof(struct sockaddr_in6));
                    break;
                }
        }

        if (rp == NULL) {
            LOGE("failed to resolve remote addr");
            return -1;
        }

        freeaddrinfo(result);
        return 0;
    }

    return -1;
}
