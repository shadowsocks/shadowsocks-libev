#ifndef _SERVER_H
#define _SERVER_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"
#include "asyncns.h"

struct listen_ctx {
    ev_io io;
    int fd;
    int timeout;
    int method;
    char *iface;
    asyncns_t *asyncns;
    struct sockaddr sock;
};

struct server_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct server *server;
};

struct server {
    int fd;
    int buf_len;
    int buf_idx;
    char *buf; // server send from, remote recv into
    char stage;
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listen_ctx;
    asyncns_query_t *query;
    struct remote *remote;
};

struct remote_ctx {
    ev_io io;
    int connected;
    struct remote *remote;
};

struct remote {
    int fd;
    int buf_len;
    int buf_idx;
    char *buf; // remote send from, server recv into
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
};


static void accept_cb (EV_P_ ev_io *w, int revents);
static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_send_cb (EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);
static void server_resolve_cb(EV_P_ ev_timer *watcher, int revents);

struct remote* new_remote(int fd);
struct remote *connect_to_remote(struct addrinfo *res, const char *iface);
void free_remote(struct remote *remote);
void close_and_free_remote(EV_P_ struct remote *remote);
struct server* new_server(int fd, struct listen_ctx *listener);
void free_server(struct server *server);
void close_and_free_server(EV_P_ struct server *server);

#endif // _SERVER_H
