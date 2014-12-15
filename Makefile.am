if BUILD_WINCOMPAT
SUBDIRS = libsodium libcork libipset libev src
else
SUBDIRS = libsodium libcork libipset libasyncns libev src
endif

ACLOCAL_AMFLAGS = -I m4
man_MANS = shadowsocks-libev.8

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = shadowsocks-libev.pc
