/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
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

// only enable TCP_FASTOPEN on linux
#if defined(__linux__)

/*  conditional define for TCP_FASTOPEN */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN   23
#endif

/*  conditional define for MSG_FASTOPEN */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN   0x20000000
#endif

#elif !defined(__APPLE__)

#ifdef TCP_FASTOPEN
#undef TCP_FASTOPEN
#endif

#endif

#define DEFAULT_CONF_PATH "/etc/shadowsocks-libev/config.json"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#define TCP_ONLY     0
#define TCP_AND_UDP  1
#define UDP_ONLY     3

#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
#define MODULE_LOCAL
#endif

int init_udprelay(const char *server_host, const char *server_port,
#ifdef MODULE_LOCAL
                  const struct sockaddr *remote_addr, const int remote_addr_len,
#ifdef MODULE_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
                  int method, int auth, int timeout, const char *iface);

void free_udprelay(void);

#ifdef ANDROID
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

#endif // _COMMON_H
