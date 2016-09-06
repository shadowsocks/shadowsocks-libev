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
#ifndef TABLE_H
#define TABLE_H

#include <stdio.h>
#include <sys/queue.h>

#include "rule.h"

#define TABLE_NAME_LEN 20

SLIST_HEAD(table_head, table);

typedef struct table_head table_head_t;

typedef struct table {
    char *name;

    /* Runtime fields */
    int reference_count;
    rule_head_t rules;
    SLIST_ENTRY(table) entries;
} table_t ;

table_t *new_table();
int accept_table_arg(table_t *, const char *);
void add_table(table_head_t *, table_t *);
table_t *table_lookup(const table_head_t *, const char *);
void reload_tables(table_head_t *, table_head_t *);
int valid_table(table_t *);
void init_table(table_t *);
void table_ref_put(table_t *);
table_t *table_ref_get(table_t *);
void tables_reload(table_head_t *, table_head_t *);

void free_tables(table_head_t *);

#endif
