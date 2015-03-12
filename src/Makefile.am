VERSION_INFO = 1:0:0

AM_CFLAGS = -g -O2 -Wall -Werror -Wno-deprecated-declarations -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
AM_CFLAGS += -I$(top_srcdir)/libev
AM_CFLAGS += -I$(top_srcdir)/libudns
AM_CFLAGS += -I$(top_srcdir)/libipset/include
AM_CFLAGS += -I$(top_srcdir)/libcork/include
AM_CFLAGS += -I$(top_srcdir)/libsodium/src/libsodium/include

AM_LDFLAGS = -static

SS_COMMON_LIBS = $(top_builddir)/libev/libev.la \
                 $(top_builddir)/libipset/libipset.la \
                 $(top_builddir)/libcork/libcork.la \
                 $(top_builddir)/libsodium/src/libsodium/libsodium.la \
                 $(INET_NTOP_LIB)

bin_PROGRAMS = ss-local ss-tunnel
if !BUILD_WINCOMPAT
bin_PROGRAMS += ss-server
endif

ss_local_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   encrypt.c \
                   udprelay.c \
                   cache.c \
                   acl.c \
                   netutils.c \
                   bitcoin.c \
                   local.c

ss_tunnel_SOURCES = utils.c \
                    jconf.c \
                    json.c \
                    encrypt.c \
                    udprelay.c \
                    cache.c \
                    netutils.c \
                    tunnel.c

ss_server_SOURCES = utils.c \
                    jconf.c \
                    json.c \
                    encrypt.c \
                    udprelay.c \
                    cache.c \
                    acl.c \
                    resolv.c \
                    bitcoin.c \
                    server.c

ss_local_LDADD = $(SS_COMMON_LIBS)
ss_tunnel_LDADD = $(SS_COMMON_LIBS)
ss_server_LDADD = $(SS_COMMON_LIBS)
ss_local_LDADD += $(top_builddir)/libudns/libudns.la -lpthread
ss_tunnel_LDADD += $(top_builddir)/libudns/libudns.la
ss_server_LDADD += $(top_builddir)/libudns/libudns.la  -lpthread

ss_local_CFLAGS = $(AM_CFLAGS) -DUDPRELAY_LOCAL
ss_tunnel_CFLAGS = $(AM_CFLAGS) -DUDPRELAY_LOCAL -DUDPRELAY_TUNNEL
ss_server_CFLAGS = $(AM_CFLAGS) -DUDPRELAY_REMOTE

if BUILD_WINCOMPAT
ss_local_SOURCES += win32.c
ss_tunnel_SOURCES += win32.c
endif

if BUILD_REDIRECTOR
bin_PROGRAMS += ss-redir
ss_redir_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   encrypt.c \
                   netutils.c \
                   redir.c
ss_redir_LDADD = $(SS_COMMON_LIBS)
ss_redir_LDADD += $(top_builddir)/libudns/libudns.la
endif

lib_LTLIBRARIES = libshadowsocks.la
libshadowsocks_la_SOURCES = $(ss_local_SOURCES)
libshadowsocks_la_CFLAGS = $(ss_local_CFLAGS) -DLIB_ONLY
libshadowsocks_la_LDFLAGS = -version-info $(VERSION_INFO)
libshadowsocks_la_LIBADD = $(ss_local_LDADD)
include_HEADERS = shadowsocks.h
