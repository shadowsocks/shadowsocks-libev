/*
 * cache.c - Manage the connection cache for UDPRELAY
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

/*
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#include <errno.h>
#include <stdlib.h>
#include "cache.h"

#ifdef __MINGW32__
#include "win32.h"
#endif

/** Creates a new cache object
 *
 *  @param dst
 *  Where the newly allocated cache object will be stored in
 *
 *  @param capacity
 *  The maximum number of elements this cache object can hold
 *
 *  @return EINVAL if dst is NULL, ENOMEM if malloc fails, 0 otherwise
 */
int cache_create(struct cache **dst, const size_t capacity,
                 void (*free_cb)(void *element))
{
    struct cache *new = NULL;

    if (!dst) {
        return EINVAL;
    }

    if ((new = malloc(sizeof(*new))) == NULL) {
        return ENOMEM;
    }

    new->max_entries = capacity;
    new->entries     = NULL;
    new->free_cb     = free_cb;
    *dst             = new;
    return 0;
}

/** Frees an allocated cache object
 *
 *  @param cache
 *  The cache object to free
 *
 *  @param keep_data
 *  Whether to free contained data or just delete references to it
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int cache_delete(struct cache *cache, int keep_data)
{
    struct cache_entry *entry, *tmp;

    if (!cache) {
        return EINVAL;
    }

    if (keep_data) {
        HASH_CLEAR(hh, cache->entries);
    } else {
        HASH_ITER(hh, cache->entries, entry, tmp){
            HASH_DEL(cache->entries, entry);
            if (entry->data != NULL) {
                if (cache->free_cb) {
                    cache->free_cb(entry->data);
                }
            }
            free(entry->key);
            free(entry);
        }
    }

    free(cache);
    cache = NULL;
    return 0;
}

/** Removes a cache entry
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key of the entry to remove
 *
 *  @param key_len
 *  The length of key
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int cache_remove(struct cache *cache, char *key, size_t key_len)
{
    struct cache_entry *tmp;

    if (!cache || !key) {
        return EINVAL;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);

    if (tmp) {
        HASH_DEL(cache->entries, tmp);
        if (tmp->data != NULL) {
            if (cache->free_cb) {
                cache->free_cb(tmp->data);
            } else {
                free(tmp->data);
            }
        }
        free(tmp->key);
        free(tmp);
    }

    return 0;
}

/** Checks if a given key is in the cache
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key to look-up
 *
 *  @param key_len
 *  The length of key
 *
 *  @param result
 *  Where to store the result if key is found.
 *
 *  A warning: Even though result is just a pointer,
 *  you have to call this function with a **ptr,
 *  otherwise this will blow up in your face.
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int cache_lookup(struct cache *cache, char *key, size_t key_len, void *result)
{
    struct cache_entry *tmp = NULL;
    char **dirty_hack       = result;

    if (!cache || !key || !result) {
        return EINVAL;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);
    if (tmp) {
        HASH_DELETE(hh, cache->entries, tmp);
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        *dirty_hack = tmp->data;
    } else {
        *dirty_hack = result = NULL;
    }

    return 0;
}

int cache_key_exist(struct cache *cache, char *key, size_t key_len)
{
    struct cache_entry *tmp = NULL;

    if (!cache || !key) {
        return 0;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);
    if (tmp) {
        HASH_DELETE(hh, cache->entries, tmp);
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        return 1;
    } else {
        return 0;
    }

    return 0;
}

/** Inserts a given <key, value> pair into the cache
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key that identifies <value>
 *
 *  @param key_len
 *  The length of key
 *
 *  @param data
 *  Data associated with <key>
 *
 *  @return EINVAL if cache is NULL, ENOMEM if malloc fails, 0 otherwise
 */
int cache_insert(struct cache *cache, char *key, size_t key_len, void *data)
{
    struct cache_entry *entry     = NULL;
    struct cache_entry *tmp_entry = NULL;

    if (!cache) {
        return EINVAL;
    }

    if ((entry = malloc(sizeof(*entry))) == NULL) {
        return ENOMEM;
    }

    entry->key = malloc(key_len);
    memcpy(entry->key, key, key_len);
    entry->data = data;
    HASH_ADD_KEYPTR(hh, cache->entries, entry->key, key_len, entry);

    if (HASH_COUNT(cache->entries) >= cache->max_entries) {
        HASH_ITER(hh, cache->entries, entry, tmp_entry){
            HASH_DELETE(hh, cache->entries, entry);
            if (entry->data != NULL) {
                if (cache->free_cb) {
                    cache->free_cb(entry->data);
                } else {
                    free(entry->data);
                }
            }
            free(entry->key);
            free(entry);
            break;
        }
    }

    return 0;
}
