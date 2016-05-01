/*
 * cache.c - Define the cache manager interface
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
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

/*
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#ifndef _CACHE_
#define _CACHE_

#include "uthash.h"

/**
 * A cache entry
 */
struct cache_entry {
    char *key;         /**<The key */
    void *data;        /**<Payload */
    UT_hash_handle hh; /**<Hash Handle for uthash */
};

/**
 * A cache object
 */
struct cache {
    size_t max_entries;              /**<Amount of entries this cache object can hold */
    struct cache_entry *entries;     /**<Head pointer for uthash */
    void (*free_cb) (void *element); /**<Callback function to free cache entries */
};

extern int cache_create(struct cache **dst, const size_t capacity,
                        void (*free_cb)(void *element));
extern int cache_delete(struct cache *cache, int keep_data);
extern int cache_lookup(struct cache *cache, char *key, size_t key_len, void *result);
extern int cache_insert(struct cache *cache, char *key, size_t key_len, void *data);
extern int cache_remove(struct cache *cache, char *key, size_t key_len);
extern int cache_key_exist(struct cache *cache, char *key, size_t key_len);

#endif
