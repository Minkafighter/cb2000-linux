#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! pkg-config --exists libfprint-2-tod-1; then
  echo "Missing 'libfprint-2-tod-1' development package." >&2
  echo "" >&2
  echo "Install it first for your distro:" >&2
  echo "  - CachyOS / Arch Linux (AUR):" >&2
  echo "      paru -S libfprint-tod fprintd" >&2
  echo "  - Ubuntu / Debian:" >&2
  echo "      sudo apt update && sudo apt install libfprint-2-tod1 libfprint-2-tod-dev fprintd libpam-fprintd" >&2
  exit 1
fi

TOD_DRIVERS_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"
if [[ -z "$TOD_DRIVERS_DIR" ]]; then
  echo "Could not resolve 'tod_driversdir' from pkg-config libfprint-2-tod-1" >&2
  exit 1
fi

echo "[1/5] Building Rust staticlib (cb2000-tod) and libfprint TOD shared module..."
if [[ -n "${SUDO_USER:-}" ]]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  USER_PATH="$USER_HOME/.cargo/bin:$PATH"
  su -s /bin/bash "$SUDO_USER" -c "PATH='$USER_PATH' make -C '$SCRIPT_DIR'"
else
  make -C "$SCRIPT_DIR"
fi

echo "[2/5] Installing libfprint-2-tod-1-cb2000.so into $TOD_DRIVERS_DIR..."
install -Dm755 "$SCRIPT_DIR/libfprint-2-tod-1-cb2000.so" "$TOD_DRIVERS_DIR/libfprint-2-tod-1-cb2000.so"

echo "[3/5] Installing udev rule and USB autosuspend hwdb..."
install -Dm644 "$REPO_ROOT/packaging/60-cb2000-fingerprint.rules" /etc/udev/rules.d/60-cb2000-fingerprint.rules
install -Dm644 "$REPO_ROOT/packaging/70-cb2000-autosuspend.hwdb" /etc/udev/hwdb.d/70-cb2000-autosuspend.hwdb
systemd-hwdb update
udevadm control --reload-rules
udevadm trigger --subsystem-match=usb --attr-match=idVendor=2df0 --attr-match=idProduct=0007 || true

echo "[4/5] Ensuring stock fprintd.service owns net.reactivated.Fprint..."
if systemctl is-active --quiet cb2000-fprintd.service 2>/dev/null || systemctl is-enabled --quiet cb2000-fprintd.service 2>/dev/null; then
  systemctl disable --now cb2000-fprintd.service || true
fi
if [[ -L /etc/systemd/system/fprintd.service ]] || [[ "$(systemctl is-enabled fprintd.service 2>/dev/null || true)" == "masked" ]]; then
  systemctl unmask fprintd.service || true
fi

echo "[5/5] Restarting fprintd.service..."
systemctl restart fprintd.service || true

echo ""
echo "Done! Verify with:"
echo "  fprintd-list \"${SUDO_USER:-$USER}\""
echo "  fprintd-enroll"
