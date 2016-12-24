/*
 * obfs_http.c - Implementation of http obfuscating
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>

#include "base64.h"
#include "utils.h"
#include "obfs_http.h"

static const char *http_request_template =
    "GET / HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: curl/7.%d.%d\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "\r\n";

static const char *http_response_template =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Server: nginx/1.%d.%d\r\n"
    "Date: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "\r\n";

static int obfs_http_request(buffer_t *, size_t, obfs_t *);
static int obfs_http_response(buffer_t *, size_t, obfs_t *);
static int deobfs_http_header(buffer_t *, size_t, obfs_t *);
static int check_http_header(buffer_t *buf);
static void disable_http(obfs_t *obfs);
static int is_enable_http(obfs_t *obfs);

static obfs_para_t obfs_http_st = {
    .name            = "http",
    .port            = 80,
    .obfs_request    = &obfs_http_request,
    .obfs_response   = &obfs_http_response,
    .deobfs_request  = &deobfs_http_header,
    .deobfs_response = &deobfs_http_header,
    .check_obfs      = &check_http_header,
    .disable         = &disable_http,
    .is_enable       = &is_enable_http
};

obfs_para_t *const obfs_http = &obfs_http_st;

static int
obfs_http_request(buffer_t *buf, size_t cap, obfs_t *obfs)
{

    if (obfs == NULL || obfs->obfs_stage != 0) return 0;
    obfs->obfs_stage++;

    static int major_version = 0;
    static int minor_version = 0;

    major_version = major_version ? major_version : rand() % 51;
    minor_version = minor_version ? minor_version : rand() % 2;

    char host_port[256];
    char http_header[512];
    uint8_t key[16];
    char b64[64];

    if (obfs_http->port != 80)
        snprintf(host_port, sizeof(host_port), "%s:%d", obfs_http->host, obfs_http->port);
    else
        snprintf(host_port, sizeof(host_port), "%s", obfs_http->host);

    rand_bytes(key, 16);
    base64_encode(b64, 64, key, 16);

    size_t obfs_len =
        snprintf(http_header, sizeof(http_header), http_request_template,
                 host_port, major_version, minor_version, b64);
    size_t buf_len = buf->len;

    brealloc(buf, obfs_len + buf_len, cap);

    memmove(buf->data + obfs_len, buf->data, buf_len);
    memcpy(buf->data, http_header, obfs_len);

    buf->len = obfs_len + buf_len;

    return buf->len;
}

static int
obfs_http_response(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    if (obfs == NULL || obfs->obfs_stage != 0) return 0;
    obfs->obfs_stage++;

    static int major_version = 0;
    static int minor_version = 0;

    major_version = major_version ? major_version : rand() % 11;
    minor_version = minor_version ? minor_version : rand() % 12;

    char http_header[512];
    char datetime[64];
    uint8_t key[16];
    char b64[64];

    time_t now;
    struct tm *tm_now;

    time(&now);
    tm_now = localtime(&now);
    strftime(datetime, 64, "%a, %d %b %Y %H:%M:%S GMT", tm_now);

    rand_bytes(key, 16);
    base64_encode(b64, 64, key, 16);

    size_t buf_len  = buf->len;
    size_t obfs_len =
        snprintf(http_header, sizeof(http_header), http_response_template,
                 major_version, minor_version, datetime, b64);

    brealloc(buf, obfs_len + buf_len, cap);

    memmove(buf->data + obfs_len, buf->data, buf_len);
    memcpy(buf->data, http_header, obfs_len);

    buf->len = obfs_len + buf_len;

    return buf->len;
}

static int
deobfs_http_header(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    if (obfs == NULL || obfs->deobfs_stage != 0) return 0;

    char *data = buf->data;
    int len    = buf->len;
    int err    = -1;

    while (len > 4) {
        if (data[0] == '\r' && data[1] == '\n'
            && data[2] == '\r' && data[3] == '\n') {
            len  -= 4;
            data += 4;
            err   = 0;
            break;
        }
        len--;
        data++;
    }

    if (!err) {
        memmove(buf->data, data, len);
        buf->len = len;
        obfs->deobfs_stage++;
    }

    return err;
}

static int
check_http_header(buffer_t *buf)
{
    char *data = buf->data;
    int len    = buf->len;

    if (len < 4)
        return -1;

    if (strncasecmp(data, "GET", 3) == 0)
        return 1;
    else if (strncasecmp(data, "HTTP", 4) == 0)
        return 1;

    return 0;
}

static void
disable_http(obfs_t *obfs)
{
    obfs->obfs_stage = -1;
    obfs->deobfs_stage = -1;
}

static int
is_enable_http(obfs_t *obfs)
{
    return obfs->obfs_stage == 0 && obfs->deobfs_stage == 0;
}
