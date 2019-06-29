/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
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

#ifndef _COMMON_H
#define _COMMON_H

#include <libcork/ds.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#ifdef __MINGW32__
#include "winsock.h"
#endif

#include "crypto.h"
#include "jconf.h"
#include "protocol.h"
#include "shadowsocks.h"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifdef MODULE_REMOTE
#ifdef MODULE_
#error "MODULE_REMOTE and MODULE_LOCAL should not be both defined"
#endif
#endif

#ifdef MODULE_LOCAL
#define MODULE_SOCKS
#endif

#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
#define MODULE_LOCAL
#endif

typedef struct remote_cnf {
    char *iface;
    crypto_t *crypto;
    struct sockaddr_storage *addr;
} remote_cnf_t;

typedef struct listen_ctx {
    ev_io io;
    int fd;
    int timeout;
    int tos;
    int mptcp;
    int reuse_port;
    int mtu;
    char *iface;

#ifdef MODULE_LOCAL
    int remote_num;
    struct remote_cnf **remotes;
#ifdef MODULE_TUNNEL
    struct ssocks_addr destaddr;
#endif
#elif MODULE_REMOTE
    crypto_t *crypto;
#ifndef __MINGW32__
    ev_timer stat_watcher;
#endif
    struct cork_dllist_item entries;
#endif
    struct ev_loop *loop;
    struct sockaddr_storage *addr;
} listen_ctx_t;

#ifdef __ANDROID__
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

void init_udprelay(listen_ctx_t *listener);
void free_udprelay(struct ev_loop *loop);

#endif // _COMMON_H
