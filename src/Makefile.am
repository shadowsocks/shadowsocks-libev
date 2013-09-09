AM_CFLAGS = -g -O2 -Wall -fno-strict-aliasing
AM_CFLAGS += -I$(top_builddir)/libev
AM_CFLAGS += -I$(top_builddir)/libasyncns

AM_LDFLAGS = -static

SS_COMMON_LIBS = $(top_builddir)/libev/libev.la $(INET_NTOP_LIB)
 
bin_PROGRAMS = ss-local

if !BUILD_WINCOMPAT
bin_PROGRAMS += ss-server
endif

ss_local_SOURCES = utils.c \
                   jconf.c \
                   json.c \
		   encrypt.c \
		   udprelay.c \
		   cache.c \
		   local.c
ss_server_SOURCES = utils.c \
                    jconf.c \
                    json.c \
                    encrypt.c \
		    udprelay.c \
		    cache.c \
                    server.c
ss_local_LDADD = $(SS_COMMON_LIBS)
ss_server_LDADD = $(SS_COMMON_LIBS)
ss_server_LDADD += $(top_builddir)/libasyncns/libasyncns.la

ss_local_CFLAGS = $(AM_CFLAGS) -DUDPRELAY_LOCAL
ss_server_CFLAGS = $(AM_CFLAGS) -DUDPRELAY_REMOTE

if BUILD_WINCOMPAT
ss_local_SOURCES += win32.c
endif

if BUILD_REDIRECTOR
bin_PROGRAMS += ss-redir
ss_redir_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   encrypt.c \
                   redir.c
ss_redir_LDADD = $(SS_COMMON_LIBS)
endif

