/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * Copyright (c) 2011 Manuel Kasper <mk@neon1.net>
 * Copyright (c) 2017 Syrone Wong <wong.syrone@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "rule.h"
#include "utils.h"

static void free_rule(rule_t *);

rule_t *
new_rule()
{
    rule_t *rule;

    rule = calloc(1, sizeof(rule_t));
    if (rule == NULL) {
        ERROR("malloc");
        return NULL;
    }

    return rule;
}

int
accept_rule_arg(rule_t *rule, const char *arg)
{
    if (rule->pattern == NULL) {
        rule->pattern = strdup(arg);
        if (rule->pattern == NULL) {
            ERROR("strdup failed");
            return -1;
        }
    } else {
        LOGE("Unexpected table rule argument: %s", arg);
        return -1;
    }

    return 1;
}

void
add_rule(struct cork_dllist *rules, rule_t *rule)
{
    cork_dllist_add(rules, &rule->entries);
}

/*
 * XXX: As pattern and subject are char arguments, they can be straightforwardly
 *      cast to PCRE2_SPTR as we are working in 8-bit code units.
 */

int
init_rule(rule_t *rule)
{
    if (rule->pattern_re == NULL) {
        int errornumber;
        PCRE2_SIZE erroroffset;
        rule->pattern_re = pcre2_compile(
            (PCRE2_SPTR)rule->pattern,   /* the pattern */
            PCRE2_ZERO_TERMINATED,       /* indicates pattern is zero-terminated */
            0,                           /* default options */
            &errornumber,                /* for error number */
            &erroroffset,                /* for error offset */
            NULL);                       /* use default compile context */

        if (rule->pattern_re == NULL) {
            PCRE2_UCHAR errbuffer[512];
            pcre2_get_error_message(errornumber, errbuffer, sizeof(errbuffer));
            LOGE("PCRE2 regex compilation failed at offset %d: %s\n", (int)erroroffset,
                 errbuffer);
            return 0;
        }

        rule->pattern_re_match_data = pcre2_match_data_create_from_pattern(rule->pattern_re, NULL);
    }

    return 1;
}

rule_t *
lookup_rule(const struct cork_dllist *rules, const char *name, size_t name_len)
{
    struct cork_dllist_item *curr, *next;

    if (name == NULL) {
        name     = "";
        name_len = 0;
    }

    cork_dllist_foreach_void(rules, curr, next) {
        rule_t *rule = cork_container_of(curr, rule_t, entries);
        if (pcre2_match(
                rule->pattern_re,            /* the compiled pattern */
                (PCRE2_SPTR)name,            /* the subject string */
                name_len,                    /* the length of the subject */
                0,                           /* start at offset 0 in the subject */
                0,                           /* default options */
                rule->pattern_re_match_data, /* block for storing the result */
                NULL                         /* use default match context */
                ) >= 0)
            return rule;
    }

    return NULL;
}

void
remove_rule(rule_t *rule)
{
    cork_dllist_remove(&rule->entries);
    free_rule(rule);
}

static void
free_rule(rule_t *rule)
{
    if (rule == NULL)
        return;

    ss_free(rule->pattern);
    if (rule->pattern_re != NULL) {
        pcre2_match_data_free(rule->pattern_re_match_data);   /* Release memory used for the match */
        pcre2_code_free(rule->pattern_re);                    /* data and the compiled pattern. */
        rule->pattern_re_match_data = NULL;
        rule->pattern_re            = NULL;
    }
    ss_free(rule);
}
