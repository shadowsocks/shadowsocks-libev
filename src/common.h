/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
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

#ifndef _INCLUDE_H
#define _INCLUDE_H

// only enable TCP_FASTOPEN on linux
#if __linux

/*  conditional define for TCP_FASTOPEN */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN   23
#endif

/*  conditional define for MSG_FASTOPEN */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN   0x20000000
#endif

#endif

#define DEFAULT_CONF_PATH "./config.json"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

int init_udprelay(const char *server_host, const char *server_port,
#ifdef UDPRELAY_LOCAL
                  const struct sockaddr *remote_addr, const int remote_addr_len,
#ifdef UDPRELAY_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
                  int method, int timeout, const char *iface);

void free_udprelay(void);

#endif // _INCLUDE_H
