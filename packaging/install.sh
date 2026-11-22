#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -x "$REPO_ROOT/bin/cb2000-fprintd" ]] && [[ -x "$REPO_ROOT/bin/cb2000-cli" ]]; then
  BIN_DIR="$REPO_ROOT/bin"
elif [[ -x "$REPO_ROOT/target/release/cb2000-fprintd" ]] && [[ -x "$REPO_ROOT/target/release/cb2000-cli" ]]; then
  BIN_DIR="$REPO_ROOT/target/release"
else
  echo "Release binaries (cb2000-fprintd, cb2000-cli) not found in:" >&2
  echo "  $REPO_ROOT/bin" >&2
  echo "  $REPO_ROOT/target/release" >&2
  echo "Either extract a prebuilt release tarball or build from source as your normal user:" >&2
  echo "  cargo build --release --workspace" >&2
  exit 1
fi

echo "[1/6] Installing binaries from $BIN_DIR to /usr/local/bin..."
install -Dm755 "$BIN_DIR/cb2000-fprintd" /usr/local/bin/cb2000-fprintd
install -Dm755 "$BIN_DIR/cb2000-cli" /usr/local/bin/cb2000-cli

echo "[2/6] Installing udev rule..."
install -Dm644 "$SCRIPT_DIR/60-cb2000-fingerprint.rules" /etc/udev/rules.d/60-cb2000-fingerprint.rules
udevadm control --reload-rules
udevadm trigger --subsystem-match=usb --attr-match=idVendor=2df0 --attr-match=idProduct=0007 || true

echo "[3/6] Installing D-Bus policy & activation files..."
install -Dm644 "$SCRIPT_DIR/net.reactivated.Fprint.conf" /etc/dbus-1/system.d/net.reactivated.Fprint.conf
install -Dm644 "$SCRIPT_DIR/net.reactivated.Fprint.service" /usr/share/dbus-1/system-services/net.reactivated.Fprint.service

echo "[4/6] Installing Polkit policy (if not already provided by fprintd)..."
if [[ ! -f /usr/share/polkit-1/actions/net.reactivated.fprint.device.policy ]]; then
  install -Dm644 "$SCRIPT_DIR/net.reactivated.fprint.device.policy" /usr/share/polkit-1/actions/net.reactivated.fprint.device.policy
fi

echo "[5/6] Masking upstream fprintd.service (if installed) to prevent D-Bus conflict..."
if systemctl list-unit-files fprintd.service &>/dev/null; then
  systemctl stop fprintd.service 2>/dev/null || true
  systemctl mask fprintd.service 2>/dev/null || true
fi

echo "[6/6] Installing and enabling cb2000-fprintd.service..."
install -Dm644 "$SCRIPT_DIR/cb2000-fprintd.service" /etc/systemd/system/cb2000-fprintd.service
systemctl daemon-reload
systemctl enable cb2000-fprintd.service
systemctl restart cb2000-fprintd.service

echo ""
echo "Done! Check daemon status with:"
echo "  systemctl status cb2000-fprintd.service"
echo "  journalctl -u cb2000-fprintd.service -n 30"
