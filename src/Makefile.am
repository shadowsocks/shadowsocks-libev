bin_PROGRAMS = ss-local ss-server
ss_local_SOURCES = utils.c jconf.c json.c \
				   encrypt.c \
				   local.c
ss_server_SOURCES = utils.c jconf.c json.c \
					encrypt.c \
					server.c
ss_local_LDADD = $(top_builddir)/libev/libev.la
ss_server_LDADD = $(top_builddir)/libev/libev.la
ss_server_LDADD += $(top_builddir)/libasyncns/libasyncns.la

if BUILD_REDIRECTOR
bin_PROGRAMS += ss-redir
ss_redir_SOURCES = utils.c jconf.c json.c \
				   encrypt.c \
				   redir.c
ss_redir_LDADD = $(top_builddir)/libev/libev.la
endif

AM_CFLAGS  = -g -O2 -Wall -fno-strict-aliasing 
AM_LDFLAGS = -static
AM_CFLAGS += -I$(top_builddir)/libev
AM_CFLAGS += -I$(top_builddir)/libasyncns
