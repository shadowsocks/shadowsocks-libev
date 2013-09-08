#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include "encrypt.h"
#include "jconf.h"

struct listen_ctx
{
    ev_io io;
    char **remote_host;
    char *remote_port;
    int remote_num;
    int timeout;
    int fd;
    int method;
    struct sockaddr sock;
};

struct server_ctx
{
    ev_io io;
    int connected;
    struct server *server;
};

struct server
{
    int fd;
    int buf_len;
    int buf_idx;
    char *buf; // server send from, remote recv into
    struct sockaddr_in destaddr;
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct remote *remote;
};

struct remote_ctx
{
    ev_io io;
    ev_timer watcher;
    int connected;
    struct remote *remote;
};

struct remote
{
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
struct remote* new_remote(int fd, int timeout);
void free_remote(struct remote *remote);
void close_and_free_remote(EV_P_ struct remote *remote);
struct server* new_server(int fd, int method);
void free_server(struct server *server);
void close_and_free_server(EV_P_ struct server *server);

#endif // _LOCAL_H
