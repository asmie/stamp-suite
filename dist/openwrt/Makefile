include $(TOPDIR)/rules.mk

PKG_NAME:=stamp-suite
PKG_VERSION:=0.6.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/asmie/stamp-suite/tar.gz/v$(PKG_VERSION)?
# TODO: Replace with real SHA256 before feed submission.
# Generate with: curl -sL <tarball-url> | sha256sum
PKG_HASH:=skip

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Piotr Olszewski <asmie@asmie.pl>

PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk
include ../../lang/rust/rust-package.mk

define Package/stamp-suite
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Simple Two-Way Active Measurement Protocol (STAMP)
  URL:=https://github.com/asmie/stamp-suite
  DEPENDS:=$(RUST_ARCH_DEPENDS)
endef

define Package/stamp-suite/description
  stamp-suite is a Rust implementation of the Simple Two-Way Active
  Measurement Protocol (STAMP) as defined in RFC 8762 and RFC 8972.
  It provides a client-server application pair for measuring packet
  loss and network delays.
endef

define Package/stamp-suite/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/stamp-suite $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/stamp-suite.init $(1)/etc/init.d/stamp-suite
endef

$(eval $(call RustBinPackage,stamp-suite))
$(eval $(call BuildPackage,stamp-suite))
