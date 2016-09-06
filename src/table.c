/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "table.h"
#include "rule.h"
#include "utils.h"

static void free_table(table_t *);

static inline rule_t *
table_lookup_rule(const table_t *table, const char *name, size_t name_len) {
    return lookup_rule(&table->rules, name, name_len);
}

static inline void __attribute__((unused))
remove_table_rule(table_t *table, rule_t *rule) {
    remove_rule(&table->rules, rule);
}


table_t *
new_table() {
    table_t *table;

    table = malloc(sizeof(table_t));
    if (table == NULL) {
        LOGE("malloc: %s", strerror(errno));
        return NULL;
    }

    table->name = NULL;
    table->reference_count = 0;
    STAILQ_INIT(&table->rules);

    return table;
}

int
accept_table_arg(table_t *table, const char *arg) {
    if (table->name == NULL) {
        table->name = strdup(arg);
        if (table->name == NULL) {
            LOGE("strdup: %s", strerror(errno));
            return -1;
        }
    } else {
        LOGE("Unexpected table argument: %s", arg);
        return -1;
    }

    return 1;
}


void
add_table(table_head_t *tables, table_t *table) {
    table_ref_get(table);
    SLIST_INSERT_HEAD(tables, table, entries);
}

void init_table(table_t *table) {
    rule_t *iter;

    STAILQ_FOREACH(iter, &table->rules, entries)
        init_rule(iter);
}

void
free_tables(table_head_t *tables) {
    table_t *iter;

    while ((iter = SLIST_FIRST(tables)) != NULL) {
        SLIST_REMOVE_HEAD(tables, entries);
        table_ref_put(iter);
    }
}

table_t *
table_lookup(const table_head_t *tables, const char *name) {
    table_t *iter;

    SLIST_FOREACH(iter, tables, entries) {
        if (iter->name == NULL && name == NULL) {
            return iter;
        } else if (iter->name != NULL && name != NULL &&
                strcmp(iter->name, name) == 0) {
            return iter;
        }
    }

    return NULL;
}

void
remove_table(table_head_t *tables, table_t *table) {
    SLIST_REMOVE(tables, table, table, entries);
    table_ref_put(table);
}

void
reload_tables(table_head_t *tables, table_head_t *new_tables) {
    table_t *iter;

    /* Remove unused tables which were removed from the new configuration */
    /* Unused elements at the beginning of the list */
    while ((iter = SLIST_FIRST(tables)) != NULL &&
            table_lookup(new_tables, SLIST_FIRST(tables)->name) == NULL) {
        SLIST_REMOVE_HEAD(tables, entries);
        table_ref_put(iter);
    }
    /* Remove elements following first used element */
    SLIST_FOREACH(iter, tables, entries) {
        if (SLIST_NEXT(iter, entries) != NULL &&
                table_lookup(new_tables,
                        SLIST_NEXT(iter, entries)->name) == NULL) {
            table_t *temp = SLIST_NEXT(iter, entries);
            /* SLIST remove next */
            SLIST_NEXT(iter, entries) = SLIST_NEXT(temp, entries);
            table_ref_put(temp);
        }
    }


    while ((iter = SLIST_FIRST(new_tables)) != NULL) {
        SLIST_REMOVE_HEAD(new_tables, entries);

        /* Initialize table regular expressions */
        init_table(iter);

        table_t *existing = table_lookup(tables, iter->name);
        if (existing) {
            /* Swap table contents */
            rule_head_t temp = existing->rules;
            existing->rules = iter->rules;
            iter->rules = temp;
        } else {
            add_table(tables, iter);
        }
        table_ref_put(iter);
    }
}

static void
free_table(table_t *table) {
    rule_t *iter;

    if (table == NULL)
        return;

    while ((iter = STAILQ_FIRST(&table->rules)) != NULL)
        remove_rule(&table->rules, iter);

    free(table->name);
    free(table);
}

void
table_ref_put(table_t *table) {
    if (table == NULL)
        return;

    assert(table->reference_count > 0);
    table->reference_count--;
    if (table->reference_count == 0)
        free_table(table);
}

table_t *
table_ref_get(table_t *table) {
    table->reference_count++;
    return table;
}
