if USE_SYSTEM_SHARED_LIB
SUBDIRS = libcork libipset src Doc
else
SUBDIRS = libsodium libcork libipset libudns libev src Doc
endif

ACLOCAL_AMFLAGS = -I m4

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = shadowsocks-libev.pc
