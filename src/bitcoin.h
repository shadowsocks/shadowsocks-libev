/*
 * bitcoin.h
 *
 * Copyright (C) 2015, Kevin Pan <bit.kevin@gmail.com>
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
#ifndef _BITCOIN_H
#define _BITCOIN_H

#include <stddef.h>

extern int bitcoin_sign_message(unsigned char *buf_65,
                                const void *msg, const size_t msg_len,
                                const char *priv_key_b58, const char *address);

extern int bitcoin_verify_message(const char *address, const unsigned char *sig_65,
                                  const void *msg, const size_t msglen);

struct btc_client;
struct btc_list;
extern struct btc_list *bitcoin_init_list();
extern int bitcoin_check_address(struct btc_list *list, const char *address);
extern int bitcoin_setup_update_thread(struct btc_list *list);
extern void bitcoin_clean_update_thread(struct btc_list *list);
#endif
