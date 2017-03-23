include $(TOPDIR)/rules.mk

PKG_NAME:=openbgpd
PKG_VERSION:=6.0.0
PKG_RELEASE:=1

ifeq ($(CONFIG_PACKAGE_nvram-brcm),y)
  DEP_TARGET=nvram-brcm
else
  DEP_TARGET=nvram
endif

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)
NVRAM_DIR:=$(BUILD_DIR)/nvram

include $(INCLUDE_DIR)/package.mk

define Package/bgpd/Default
  SECTION:=net
  CATEGORY:=Network
  DEFAULT:=y
  TITLE:=Border Gateway Protocol daemon with lite version of BSD static library.
  URL:=http://www.openbgpd.org/
endef

define Package/libopenbsdcompat
  $(call Package/bgpd/Default)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE+= (library)
  DESCRIPTION+=\\\
	This package contains the lite version of BSD static library, used by bgpd/bgpctl program. \\\
	\\\
	bgpd is a Border Gateway Protocol (BGP) daemon which manages the network routing tables. Its \\\
	main purpose is to exchange information concerning “network reachability” with other BGP systems. \\\
	bgpd uses the Border Gateway Protocol, Version 4, as described in RFC 4271. 
endef

define Package/openbgpd
  $(call Package/bgpd/Default)
  DEPENDS:=$(DEP_TARGET) +libopenbsdcompat
  TITLE+= (full)
  DESCRIPTION+=\\\
	\\\
	This package contains a terminal-based front-end to the bgpctl \\\
	that can be communicate with bgpd.
endef

define Package/openbgpd/conffiles
	/etc/bgpd.conf
endef

define Build/Prepare
	rmdir $(PKG_BUILD_DIR)
	ln -s ${PWD}/$(PKG_NAME)/src $(PKG_BUILD_DIR)
	cd $(PKG_BUILD_DIR) && ./reconf && chmod 777 configure
endef

define Build/Configure
	(cd $(PKG_BUILD_DIR); \
		./configure \
			--prefix=$(STAGING_DIR) \
			--host=mips-linux-uclibc \
			CC="$(TARGET_CC)" \
			AR="$(TARGET_CROSS)ar" \
			RANLIB="$(TARGET_CROSS)ranlib" \
			CFLAGS="$(TARGET_CFLAGS) -I$(OPENSSL_DIR)/include -I$(NVRAM_DIR)/include -D_BYTE_ORDER=_BIG_ENDIAN -DHAVE_NAND -DOPENWRT -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
			LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib -L$(NVRAM_DIR) -lnvram -lpthread -lc" \
	)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)
endef

define Build/Clean
	rm -rf $(PKG_BUILD_DIR)/ipkg
	rm -rf $(PKG_BUILD_DIR)
	$(MAKE) distclean
	cd src;	./antigen.sh; cd -
endef

define Build/Distclean
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	$(MAKE) -C $(PKG_BUILD_DIR) distclean
	$(PKG_BUILD_DIR)/antigen.sh
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/lib
	$(INSTALL_LIB) $(PKG_BUILD_DIR)/openbsd-compat/libopenbsdcompat.a $(STAGING_DIR)/usr/lib
endef

define Build/UninstallDev
	rm -rf $(STAGING_DIR)/usr/lib/libopenbsdcompat.a
endef

define Package/libopenbsdcompat/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_LIB) $(PKG_BUILD_DIR)/openbsd-compat/libopenbsdcompat.a $(1)/usr/lib/
endef

define Package/openbgpd/install
	$(call Package/libopenbsdcompat/install, $(1))
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/rc.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bgpd/bgpd $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bgpctl/bgpctl $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/bgpd $(1)/etc/rc.d/bgpd
	$(INSTALL_BIN) ./files/bgpd-functions $(1)/etc/rc.d/bgpd-functions
	$(INSTALL_CONF) ./files/bgpd.conf $(1)/etc
	$(STRIP) $(1)/usr/sbin/bgpd
	$(STRIP) $(1)/usr/sbin/bgpctl
endef

$(eval $(call BuildPackage,libopenbsdcompat))
$(eval $(call BuildPackage,openbgpd))
