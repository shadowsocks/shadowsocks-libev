include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocks-libev
PKG_VERSION:=2.4.6
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_URL:=https://github.com/shadowsocks/shadowsocks-libev/archive
PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_MAINTAINER:=Max Lv <max.c.lv@gmail.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)

PKG_INSTALL:=1
PKG_FIXUP:=autoreconf
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/shadowsocks-libev/Default
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Lightweight Secured Socks5 Proxy
  URL:=https://github.com/madeye/shadowsocks-libev
endef

define Package/shadowsocks-libev
  $(call Package/shadowsocks-libev/Default)
  TITLE+= (OpenSSL)
  VARIANT:=openssl
  DEPENDS:=+libopenssl +libpthread
endef

define Package/shadowsocks-libev-polarssl
  $(call Package/shadowsocks-libev/Default)
  TITLE+= (PolarSSL)
  VARIANT:=polarssl
  DEPENDS:=+libpolarssl +libpthread
endef

define Package/shadowsocks-libev-mbedtls
  $(call Package/shadowsocks-libev/Default)
  TITLE+= (mbedTLS)
  VARIANT:=mbedtls
  DEPENDS:=+libmbedtls +libpthread
endef

define Package/shadowsocks-libev/description
Shadowsocks-libev is a lightweight secured socks5 proxy for embedded devices and low end boxes.
endef

Package/shadowsocks-libev-polarssl/description=$(Package/shadowsocks-libev/description)
Package/shadowsocks-libev-mbedtls/description=$(Package/shadowsocks-libev/description)

define Package/shadowsocks-libev/conffiles
/etc/shadowsocks.json
endef

CONFIGURE_ARGS += --disable-ssp

ifeq ($(BUILD_VARIANT),polarssl)
	CONFIGURE_ARGS += --with-crypto-library=polarssl
endif

ifeq ($(BUILD_VARIANT),mbedtls)
	CONFIGURE_ARGS += --with-crypto-library=mbedtls
endif

define Package/shadowsocks-libev/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_CONF) ./files/shadowsocks.json $(1)/etc
	$(INSTALL_BIN) ./files/shadowsocks.init $(1)/etc/init.d/shadowsocks
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/ss-{local,redir,tunnel} $(1)/usr/bin
endef

Package/shadowsocks-libev-polarssl/install=$(Package/shadowsocks-libev/install)
Package/shadowsocks-libev-mbedtls/install=$(Package/shadowsocks-libev/install)

$(eval $(call BuildPackage,shadowsocks-libev))
$(eval $(call BuildPackage,shadowsocks-libev-polarssl))
$(eval $(call BuildPackage,shadowsocks-libev-mbedtls))
