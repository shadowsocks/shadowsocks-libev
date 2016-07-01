if USE_SYSTEM_SHARED_LIB
SUBDIRS = libcork libipset src Doc
else
SUBDIRS = libsodium libcork libipset libudns libev src Doc
endif

ACLOCAL_AMFLAGS = -I m4
man_MANS = man/shadowsocks-libev.8 man/ss-server.1 man/ss-local.1 man/ss-redir.1\
	   man/ss-manager.1 man/ss-tunnel.1 man/ss-nat.1

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = shadowsocks-libev.pc
