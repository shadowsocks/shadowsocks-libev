/*
 * mm-wrapper.h - Define safe memory management wrapper
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

#ifndef _MM_WRAPPER_H
#define _MM_WRAPPER_H

#include <stdlib.h>

#define SS_SAFEFREE(ptr) \
    do {                 \
        free(ptr);       \
        ptr = NULL;      \
    } while(0)

static inline void *SS_SAFEMALLOC(size_t size);
static inline void *SS_SAFEREALLOC(void *ptr, size_t new_size);

static inline void *SS_SAFEMALLOC(size_t size) {
    void *tmp = malloc(size);
    if (tmp == NULL)
        exit(EXIT_FAILURE);
    return tmp;
}

static inline void *SS_SAFEREALLOC(void *ptr, size_t new_size) {
    void *new = realloc(ptr, new_size);
    if (new == NULL) {
        free(ptr); ptr = NULL;
        exit(EXIT_FAILURE);
    }
    return new;
}

#endif // _MM_WRAPPER_H
