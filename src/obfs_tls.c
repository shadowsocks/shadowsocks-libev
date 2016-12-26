/*
 * obfs_tls.c - Implementation of tls obfuscating
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
 * <tls://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>

#include "base64.h"
#include "utils.h"
#include "obfs_tls.h"

static const struct tls_client_hello
tls_client_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = 0,

    .handshake_type = 1,
    .handshake_len_1 = 0,
    .handshake_len_2 = 0,
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suites_len = CT_HTONS(56),
    .cipher_suites = { 
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
    },

    .comp_methods_len = 1,
    .comp_methods = { 0 },

    .ext_len = 0,
};

static const struct tls_ext_server_name
tls_ext_server_name_template = {
    .ext_type = 0,
    .ext_len = 0,
    .server_name_list_len = 0,
    .server_name_type = 0,
    .server_name_len = 0
    // char server_name[server_name_len];
};

static const struct tls_ext_session_ticket
tls_ext_session_ticket_template = {
    .session_ticket_type = CT_HTONS(0x0023),
    .session_ticket_ext_len = 0,
    // char  session_ticket[session_ticket_ext_len];
};

static const struct tls_ext_others 
tls_ext_others_template = {
    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(4),
    .ec_point_formats_len = 3,
    .ec_point_formats = { 0x01, 0x00, 0x02 },

    .elliptic_curves_type = CT_HTONS(0x000a),
    .elliptic_curves_ext_len = CT_HTONS(10),
    .elliptic_curves_len = CT_HTONS(8),
    .elliptic_curves = { 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18 },

    .sig_algos_type = CT_HTONS(0x000d),
    .sig_algos_ext_len = CT_HTONS(32),
    .sig_algos_len = CT_HTONS(30),
    .sig_algos = {
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
    },

    .encrypt_then_mac_type = CT_HTONS(0x0016),
    .encrypt_then_mac_ext_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0
};

static const struct tls_server_hello
tls_server_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = CT_HTONS(91),

    .handshake_type = 2,
    .handshake_len_1 = 0,
    .handshake_len_2 = CT_HTONS(87),
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suite = CT_HTONS(0xCCA8),
    .comp_method = 0,
    .ext_len = 0,

    .ext_renego_info_type = CT_HTONS(0xFF01),
    .ext_renego_info_ext_len = CT_HTONS(1),
    .ext_renego_info_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,

    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(2),
    .ec_point_formats_len = 1,
    .ec_point_formats = { 0 }
};

static const struct tls_change_cipher_spec 
tls_change_cipher_spec_template = {
    .content_type = 0x14,
    .version = CT_HTONS(0x0303),
    .len = CT_HTONS(1),
    .msg = 0x01
};

static const struct tls_encrypted_handshake
tls_encrypted_handshake_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0303),
    .len = 0
    // char  msg[len];
};

const char tls_data_header[3] = {0x17, 0x03, 0x03};


static int obfs_tls_request(buffer_t *, size_t, obfs_t *);
static int obfs_tls_response(buffer_t *, size_t, obfs_t *);
static int deobfs_tls_request(buffer_t *, size_t, obfs_t *);
static int deobfs_tls_response(buffer_t *, size_t, obfs_t *);
static int obfs_app_data(buffer_t *, size_t, obfs_t *);
static int deobfs_app_data(buffer_t *, size_t, obfs_t *);
static int check_tls_request(buffer_t *buf);
static void disable_tls(obfs_t *obfs);
static int is_enable_tls(obfs_t *obfs);

static obfs_para_t obfs_tls_st = {
    .name            = "tls",
    .port            = 443,
    .obfs_request    = &obfs_tls_request,
    .obfs_response   = &obfs_tls_response,
    .deobfs_request  = &deobfs_tls_request,
    .deobfs_response = &deobfs_tls_response,
    .check_obfs      = &check_tls_request,
    .disable         = &disable_tls,
    .is_enable       = &is_enable_tls
};

obfs_para_t *const obfs_tls = &obfs_tls_st;

static int
obfs_app_data(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    size_t buf_len = buf->len;

    brealloc(buf, buf_len + 5, cap);
    memmove(buf->data + 5, buf->data, buf_len);
    memcpy(buf->data, tls_data_header, 3);

    *(uint16_t*)(buf->data + 3) = CT_HTONS(buf_len);
    buf->len = buf_len + 5;

    return 0;
}

static int
deobfs_app_data(buffer_t *buf, size_t idx, obfs_t *obfs)
{
    int bidx = idx, bofst = idx;

    frame_t *frame = (frame_t *)obfs->extra;

    while (bidx < buf->len) {
        if (frame->len == 0) {
            if (frame->idx >= 0 && frame->idx < 3
                    && buf->data[bidx] != tls_data_header[frame->idx]) {
                return OBFS_ERROR;
            } else if (frame->idx >= 3 && frame->idx < 5) {
                memcpy(frame->buf + frame->idx - 3, buf->data + bidx, 1);
            } else if (frame->idx < 0) {
                bofst++;
            }
            frame->idx++;
            bidx++;
            if (frame->idx == 5) {
                frame->len = CT_NTOHS(*(uint16_t *)(frame->buf));
                frame->idx = 0;
            }
            continue;
        }

        int left_len = buf->len - bidx;

        if (left_len > frame->len) {
            memmove(buf->data + bofst, buf->data + bidx, frame->len);
            bidx  += frame->len;
            bofst += frame->len;
            frame->len = 0;
        } else {
            memmove(buf->data + bofst, buf->data + bidx, left_len);
            bidx  = buf->len;
            bofst += left_len;
            frame->len -= left_len;
        }
    }

    buf->len = bofst;

    return OBFS_OK;
}


static int
obfs_tls_request(buffer_t *buf, size_t cap, obfs_t *obfs)
{

    if (obfs == NULL || obfs->obfs_stage < 0) return 0;

    static buffer_t tmp = { 0, 0, 0, NULL };

    if (obfs->obfs_stage == 0) {

        size_t buf_len = buf->len;
        size_t hello_len = sizeof(struct tls_client_hello);
        size_t server_name_len = sizeof(struct tls_ext_server_name);
        size_t host_len = strlen(obfs_tls->host);
        size_t ticket_len = sizeof(struct tls_ext_session_ticket);
        size_t other_ext_len = sizeof(struct tls_ext_others);
        size_t tls_len = buf_len + hello_len + server_name_len
            + host_len + ticket_len + other_ext_len;

        brealloc(&tmp, buf_len, cap);
        brealloc(buf,  tls_len, cap);

        memcpy(tmp.data, buf->data, buf_len);

        /* Client Hello Header */
        struct tls_client_hello *hello = (struct tls_client_hello *) buf->data;
        memcpy(hello, &tls_client_hello_template, hello_len);
        hello->len = CT_HTONS(tls_len - 5);
        hello->handshake_len_2 = CT_HTONS(tls_len - 9); 
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL));
        rand_bytes(hello->random_bytes, 28);
        rand_bytes(hello->session_id, 32);
        hello->ext_len = CT_HTONS(server_name_len + host_len + ticket_len + buf_len + other_ext_len);

        /* Session Ticket */
        struct tls_ext_session_ticket *ticket =
            (struct tls_ext_session_ticket *)((char *)hello + hello_len);
        memcpy(ticket, &tls_ext_session_ticket_template, sizeof(struct tls_ext_session_ticket));
        ticket->session_ticket_ext_len = CT_HTONS(buf_len);
        memcpy((char *)ticket + ticket_len, tmp.data, buf_len);

        /* SNI */
        struct tls_ext_server_name *server_name = 
            (struct tls_ext_server_name *)((char *)ticket + ticket_len + buf_len);
        memcpy(server_name, &tls_ext_server_name_template, server_name_len);
        server_name->ext_len = CT_HTONS(host_len + 3 + 2);
        server_name->server_name_list_len = CT_HTONS(host_len + 3);
        server_name->server_name_len = CT_HTONS(host_len);
        memcpy((char *)server_name + server_name_len, obfs_tls->host, host_len);

        /* Other Extensions */
        memcpy((char *)server_name + server_name_len + host_len, &tls_ext_others_template,
                other_ext_len);

        buf->len = tls_len;

        obfs->obfs_stage++;

    } else if (obfs->obfs_stage == 1) {

        obfs_app_data(buf, cap, obfs);

    }

    return buf->len;
}

static int
obfs_tls_response(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    if (obfs == NULL || obfs->obfs_stage < 0) return 0;

    static buffer_t tmp = { 0, 0, 0, NULL };

    if (obfs->obfs_stage == 0) {

        size_t buf_len = buf->len;
        size_t hello_len = sizeof(struct tls_server_hello);
        size_t change_cipher_spec_len = sizeof(struct tls_change_cipher_spec);
        size_t encrypted_handshake_len = sizeof(struct tls_encrypted_handshake);
        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len + buf_len;

        brealloc(&tmp, buf_len, cap);
        brealloc(buf,  tls_len, cap);

        memcpy(tmp.data, buf->data, buf_len);

        /* Server Hello */
        memcpy(buf->data, &tls_server_hello_template, hello_len);
        struct tls_server_hello *hello = (struct tls_server_hello *)buf->data;
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL));
        rand_bytes(hello->random_bytes, 28);
        if (obfs->buf != NULL) {
            memcpy(hello->session_id, obfs->buf->data, 32);
        } else {
            rand_bytes(hello->session_id, 32);
        }

        /* Change Cipher Spec */
        memcpy(buf->data + hello_len, &tls_change_cipher_spec_template, change_cipher_spec_len);

        /* Encrypted Handshake */
        memcpy(buf->data + hello_len + change_cipher_spec_len, &tls_encrypted_handshake_template,
                encrypted_handshake_len);
        memcpy(buf->data + hello_len + change_cipher_spec_len + encrypted_handshake_len,
                tmp.data, buf_len);

        struct tls_encrypted_handshake *encrypted_handshake =
            (struct tls_encrypted_handshake *)(buf->data + hello_len + change_cipher_spec_len);
        encrypted_handshake->len = CT_HTONS(buf_len);

        buf->len = tls_len;

        obfs->obfs_stage++;

    } else if (obfs->obfs_stage == 1) {

        obfs_app_data(buf, cap, obfs);

    }

    return buf->len;
}

static int
deobfs_tls_request(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    if (obfs == NULL || obfs->deobfs_stage < 0) return 0;

    if (obfs->extra == NULL) {
        obfs->extra = ss_malloc(sizeof(frame_t));
        memset(obfs->extra, 0, sizeof(frame_t));
    }

    if (obfs->buf == NULL) {
        obfs->buf = (buffer_t *)ss_malloc(sizeof(buffer_t));
        balloc(obfs->buf, 32);
        obfs->buf->len = 32;
    }

    if (obfs->deobfs_stage == 0) {

        int len = buf->len;

        len -= sizeof(struct tls_client_hello);
        if (len <= 0) return OBFS_NEED_MORE;

        struct tls_client_hello *hello = (struct tls_client_hello *) buf->data;
        if (hello->content_type != tls_client_hello_template.content_type)
            return OBFS_ERROR;

        size_t hello_len = CT_NTOHS(hello->len) + 5;

        memcpy(obfs->buf->data, hello->session_id, 32);

        len -= sizeof(struct tls_ext_session_ticket);
        if (len <= 0) return OBFS_NEED_MORE;

        struct tls_ext_session_ticket *ticket = 
            (struct tls_ext_session_ticket *)(buf->data + sizeof(struct tls_client_hello));
        if (ticket->session_ticket_type != tls_ext_session_ticket_template.session_ticket_type)
            return OBFS_ERROR;

        size_t ticket_len = CT_NTOHS(ticket->session_ticket_ext_len);
        if (len < ticket_len)
            return OBFS_NEED_MORE;

        memmove(buf->data, (char *)ticket + sizeof(struct tls_ext_session_ticket), ticket_len);

        if (buf->len > hello_len) {
            memmove(buf->data + ticket_len, buf->data + hello_len, buf->len - hello_len);
        }

        buf->len = ticket_len + buf->len - hello_len;

        obfs->deobfs_stage++;

        if (buf->len > ticket_len) {
            return deobfs_app_data(buf, ticket_len, obfs);
        } else {
            ((frame_t*)obfs->extra)->idx = buf->len - ticket_len;
        }

    } else if (obfs->deobfs_stage == 1) {

        return deobfs_app_data(buf, 0, obfs);

    }

    return 0;
}

static int
deobfs_tls_response(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    if (obfs == NULL || obfs->deobfs_stage < 0) return 0;

    if (obfs->extra == NULL) {
        obfs->extra = ss_malloc(sizeof(frame_t));
        memset(obfs->extra, 0, sizeof(frame_t));
    }

    if (obfs->deobfs_stage == 0) {

        size_t hello_len = sizeof(struct tls_server_hello);

        char *data = buf->data;
        int len    = buf->len;

        len -= hello_len;
        if (len <= 0) return OBFS_NEED_MORE;

        struct tls_server_hello *hello = (struct tls_server_hello*) data;
        if (hello->content_type != tls_server_hello_template.content_type)
            return OBFS_ERROR;

        size_t change_cipher_spec_len = sizeof(struct tls_change_cipher_spec);
        size_t encrypted_handshake_len = sizeof(struct tls_encrypted_handshake);

        len -= change_cipher_spec_len + encrypted_handshake_len;
        if (len <= 0) return OBFS_NEED_MORE;

        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len;
        struct tls_encrypted_handshake *encrypted_handshake =
            (struct tls_encrypted_handshake *)(buf->data + hello_len + change_cipher_spec_len);
        size_t msg_len = CT_NTOHS(encrypted_handshake->len);

        memmove(buf->data, buf->data + tls_len, buf->len - tls_len);

        buf->len = buf->len - tls_len;

        obfs->deobfs_stage++;

        if (buf->len > msg_len) {
            return deobfs_app_data(buf, msg_len, obfs);
        } else {
            ((frame_t*)obfs->extra)->idx = buf->len - msg_len;
        }

    } else if (obfs->deobfs_stage == 1) {

        return deobfs_app_data(buf, 0, obfs);

    }


    return 0;
}

static int
check_tls_request(buffer_t *buf)
{
    char *data = buf->data;
    int len    = buf->len;

    if (len < 11)
        return OBFS_NEED_MORE;

    return data[0] == 0x16
        && data[1] == 0x03
        && data[2] == 0x01
        && data[5] == 0x01
        && data[9] == 0x03
        && data[10] == 0x03;
}

static void
disable_tls(obfs_t *obfs)
{
    obfs->obfs_stage = -1;
    obfs->deobfs_stage = -1;
}

static int
is_enable_tls(obfs_t *obfs)
{
    return obfs->obfs_stage == 0 && obfs->deobfs_stage == 0;
}
