CC ?= gcc
PKG_CONFIG ?= pkg-config
CARGO ?= cargo
INSTALL ?= install

TOD_PKG := libfprint-2-tod-1
PKGS := $(TOD_PKG) glib-2.0 gobject-2.0 gio-2.0 gusb

RUST_STATICLIB := ../target/release/libcb2000_tod.a
TARGET := libfprint-2-tod-1-cb2000.so

CFLAGS := -O2 -Wall -Wextra -fPIC -fvisibility=hidden \
	-I../crates/cb2000-tod/include \
	$(shell $(PKG_CONFIG) --cflags $(PKGS))

LDFLAGS := -shared -Wl,--exclude-libs,ALL \
	$(shell $(PKG_CONFIG) --libs $(PKGS)) \
	-lpthread -ldl -lm

.PHONY: all rust install uninstall clean check-deps

all: $(TARGET)

check-deps:
	@if ! $(PKG_CONFIG) --exists $(TOD_PKG); then \
		echo "Missing pkg-config package '$(TOD_PKG)'." >&2; \
		echo "  CachyOS / Arch: Install 'libfprint-tod' (AUR: paru -S libfprint-tod fprintd)" >&2; \
		echo "  Ubuntu / Debian: sudo apt install libfprint-2-tod1 libfprint-2-tod-dev fprintd" >&2; \
		exit 1; \
	fi

$(RUST_STATICLIB): ../Cargo.toml ../crates/cb2000-tod/Cargo.toml ../crates/cb2000-tod/src/lib.rs ../crates/cb2000-tod/include/cb2000_tod.h
	$(CARGO) build --release --manifest-path ../Cargo.toml -p cb2000-tod

rust: $(RUST_STATICLIB)

$(TARGET): check-deps cb2000_tod.c $(RUST_STATICLIB)
	$(CC) $(CFLAGS) cb2000_tod.c $(RUST_STATICLIB) $(LDFLAGS) -o $(TARGET)

install: check-deps $(TARGET)
	$(eval TOD_DIR := $(shell $(PKG_CONFIG) --variable=tod_driversdir $(TOD_PKG)))
	@test -n "$(TOD_DIR)" || { echo "Unable to determine tod_driversdir from pkg-config" >&2; exit 1; }
	$(INSTALL) -Dm755 $(TARGET) "$(DESTDIR)$(TOD_DIR)/$(TARGET)"

uninstall: check-deps
	$(eval TOD_DIR := $(shell $(PKG_CONFIG) --variable=tod_driversdir $(TOD_PKG)))
	rm -f "$(DESTDIR)$(TOD_DIR)/$(TARGET)"

clean:
	rm -f $(TARGET)
