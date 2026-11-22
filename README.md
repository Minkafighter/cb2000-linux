# CB2000 Linux Fingerprint Driver (Clean-Room Rust + Native `libfprint` TOD)

A **100% clean-room, memory-safe Rust** Linux fingerprint driver for the **CanvasBio CB2000 (`2df0:0007`)** Match-on-Chip (MoC) fingerprint sensor found in the **Samsung Galaxy Book5 360** (and compatible laptops).

> [!WARNING]
> **Disclaimer & Testing Status**
> - **Unofficial / Vibecoded**: This is a vibecoded community driver with **no official support or affiliation from CanvasBio**. Use at your own risk.
> - **Tested setup**: This driver has **only been tested on CachyOS** by installing `fprintd` (`sudo pacman -S fprintd`) and then installing the standalone `cb2000-fprintd` service using [`packaging/install.sh`](packaging/install.sh) (**Option B** below).
> - **Untested paths**: The native `libfprint` TOD plugin (`tod/`, **Option A** below) and other distributions (such as Ubuntu) have **not** been tested on real hardware.

> [!TIP]
> **Quick Start for New Users (No Rust / Compiling Required)**
>
> Want the fastest way to get fingerprint login working? Follow these 4 steps:
> 1. **Install `fprintd`**: `sudo pacman -S fprintd` (CachyOS / Arch) or `sudo apt install fprintd libpam-fprintd` (Ubuntu / Debian).
> 2. **Download & install the prebuilt binaries**: Grab the latest `cb2000-linux-v*-x86_64.tar.gz` from [GitHub Releases](https://github.com/Minkafighter/cb2000-linux/releases/latest), extract it, and run `sudo ./packaging/install.sh` inside the extracted folder.
> 3. **Enable fingerprint login in PAM**: Add `auth sufficient pam_fprintd.so` near the top of your PAM files (`/etc/pam.d/system-local-login`, `/etc/pam.d/sudo`, `/etc/pam.d/polkit-1` on Arch/CachyOS — or run `sudo pam-auth-update` on Ubuntu).
> 4. **Enroll your fingerprints**: Add them directly in **KDE Plasma** (*System Settings → Users*), **GNOME** (*Settings → Users*), or from a terminal with `fprintd-enroll`.
>
> See [**Option B**](#option-b-install-standalone-cb2000-fprintd-daemon-tested-on-cachyos--pure-rust-no-libfprint-tod-needed) and [**Enable PAM Authentication & Enroll**](#enable-pam-authentication--enroll-both-options) below for full details.

Designed for **KDE Plasma**, **GNOME**, and **`pam_fprintd.so`** on Linux through **two integration modes** backed by the exact same Rust SDCP/USB core:

1. **Native `libfprint` TOD Plugin (`libfprint-2-tod-1-cb2000.so`)** — Plugs directly into `libfprint-2-tod1` (Ubuntu) / `libfprint-tod` (Arch/CachyOS) and stock `fprintd.service`.
2. **Standalone `cb2000-fprintd` System D-Bus Daemon** — Direct `net.reactivated.Fprint` service requiring no `libfprint` rebuild when a TOD build of `libfprint` is not installed.

Both modes integrate seamlessly with:
- **KDE Plasma** (*System Settings → Users → Configure Fingerprint Authentication*, SDDM, KScreenLocker)
- **GNOME** (*Settings → Users → Fingerprint Login*, GDM, GNOME Shell)
- **PAM (`pam_fprintd.so`)** for `sudo`, login, lockscreen, and Polkit prompts
- **`fprintd-*` CLI tools** (`fprintd-enroll`, `fprintd-verify`, `fprintd-list`, `fprintd-delete`)

## Architecture

| Component | Description |
|-----------|-------------|
| `crates/cb2000-sdcp` | Pure-Rust (`#![forbid(unsafe_code)]`) Microsoft SDCP v1 cryptography: ECDH P-256, NIST SP 800-108 Counter Mode KBKDF, X.509 Model Cert parsing, ECDSA attestation (`model_cert -> pk_d -> (h_f \|\| pk_f)`), constant-time MACs, `ZeroizeOnDrop`. |
| `crates/cb2000-proto` | Pure-Rust (`#![forbid(unsafe_code)]`) CB2000 USB Match-on-Chip protocol driver (Protocol V1/V2, multi-OS partition isolation, SDCP Connect/Reconnect, capture/finger-up polling, Enroll, Identify, Slot management) + `nusb` transport. |
| `crates/cb2000-tod` | Rust `staticlib` C ABI bridge exposing `cb2000-sdcp` + `cb2000-proto` over a minimal panic-safe FFI (`crates/cb2000-tod/include/cb2000_tod.h`). `unsafe` is strictly isolated to this FFI boundary. |
| `tod/cb2000_tod.c` | Thin MIT-licensed C GObject `FpDevice` wrapper (`fpi_tod_shared_driver_get_type`) routing `libfprint` `GUsbDevice` I/O into `libcb2000_tod.a` to produce `libfprint-2-tod-1-cb2000.so`. |
| `crates/cb2000-fprintd` | Hardened System D-Bus daemon (`net.reactivated.Fprint`) with Polkit ACLs, root-owned user-to-template binding store, `NameOwnerChanged` crash cleanup, and brute-force rate limiting. |
| `crates/cb2000-cli` | Standalone CLI for probing hardware, verifying SDCP attestation, listing slots, enrolling, verifying, and deleting prints. |

## Mode Comparison

| Aspect | Native `libfprint` TOD Plugin (`tod/`) | Standalone `cb2000-fprintd` |
|--------|----------------------------------------|-----------------------------|
| Upstream `fprintd` / `libfprint` | Runs directly inside stock `fprintd` via `libfprint-2-tod-1` | Replaces `fprintd.service` on `net.reactivated.Fprint` |
| SDCP Crypto & Attestation | Full Rust verification (`model_cert` + `s_m` + `s_d` + constant-time MACs) | Full Rust verification + persistent TOFU Model Cert SHA-256 pinning |
| Memory Safety | SDCP & USB parser in Rust; minimal C GObject wrapper (`GUsbDevice`) | 100% `#![forbid(unsafe_code)]` Rust end-to-end |
| Per-user Template Isolation | Enforced by stock `fprintd` gallery + `FPI_PRINT_RAW` ID matching | Enforced by root-owned `enrollments.json` + rate limiter |
| Distro Requirement | Needs `libfprint-2-tod1` (Ubuntu stock) or `libfprint-tod` (Arch AUR) | Works with stock `libfprint` (`fprintd` only needed for `pam_fprintd.so`) |

## Security Design

1. **Mandatory SDCP Cryptography (No Plaintext Fallback)**:
   - Ephemeral NIST P-256 ECDH key agreement with OS CSPRNG (`getrandom` / `OsRng`).
   - Full ECDSA P-256 device attestation verification of the Claim chain (`model_cert -> pk_d -> ([0xC0, 0x01] \|\| h_f \|\| pk_f)`). *(Unlike draft C patches that omit Claim signature validation, every `open()` verifies `s_m`, `s_d`, and X.509 cert validity.)*
   - Fresh 32-byte CSPRNG challenge nonce on every authentication and **constant-time HMAC-SHA256 verification** (`subtle::ConstantTimeEq`) of every `AuthorizedIdentity` response.
   - Automatic memory wiping (`zeroize::ZeroizeOnDrop`) of all session keys and secrets.
2. **Dual-Boot Partition Isolation**:
   - Uses Protocol V2 multi-host partitioning with a domain-separated Linux host UUID so Linux and Windows Hello enrollments coexist cleanly on V2 sensors without colliding.
3. **Strict User-to-Template Binding & Hardening**:
   - In `cb2000-fprintd`, matched 32-byte `enrollment_id`s are bound to exact Linux usernames in `/var/lib/cb2000-fprintd/enrollments.json` (`0700`/`0600`, atomic writes, symlink refusal), protected with Polkit ACLs, per-user exponential lockout after 5 consecutive failures, and a hardened `systemd` sandbox.

## Build & Test

Requires Rust 1.78+ (`rustup`).

```bash
# Run unit & FFI round-trip tests (SDCP crypto, tamper/replay rejection, MockCb2000 emulator, cb2000-tod C ABI, store & rate limiter)
cargo test --workspace

# Build optimized release binaries and libcb2000_tod.a
cargo build --release --workspace
```

## Quick Hardware Test

```bash
sudo ./target/release/cb2000-cli probe
sudo ./target/release/cb2000-cli slots
sudo ./target/release/cb2000-cli enroll --sub-factor 7
sudo ./target/release/cb2000-cli verify
sudo ./target/release/cb2000-cli delete-all
```

---

## Option A: Install Native `libfprint` TOD Plugin (Untested on Hardware — For Stock `fprintd`)

### 1. Install `libfprint-2-tod-1` Development Headers & `fprintd`

- **Ubuntu (22.04 / 24.04+)**:
  ```bash
  sudo apt update
  sudo apt install libfprint-2-tod1 libfprint-2-tod-dev fprintd libpam-fprintd build-essential pkg-config
  ```

- **CachyOS / Arch Linux**:
  Stock Arch `libfprint` disables the TOD loader by default; install `libfprint-tod` from the AUR (drop-in replacement providing `libfprint-2-tod-1.pc`):
  ```bash
  paru -S libfprint-tod fprintd
  ```

### 2. Build & Install `libfprint-2-tod-1-cb2000.so`

```bash
chmod +x tod/install-tod.sh
sudo ./tod/install-tod.sh
```

*(Alternatively, with Meson: `cd tod && meson setup build && ninja -C build && sudo ninja -C build install`.)*

---

## Option B: Install Standalone `cb2000-fprintd` Daemon (Tested on CachyOS — Pure Rust, No `libfprint-tod` Needed)

### 1. Install `pam_fprintd` & `fprintd-*` Client Tools

- **CachyOS / Arch Linux**:
  ```bash
  sudo pacman -S fprintd
  ```
- **Ubuntu / Debian**:
  ```bash
  sudo apt update
  sudo apt install fprintd libpam-fprintd
  ```

### 2. Install `cb2000-fprintd`

#### Prebuilt Binaries (No Rust Required)

Download the latest `cb2000-linux-v*-x86_64.tar.gz` (and optionally `SHA256SUMS.txt`) from [GitHub Releases](https://github.com/Minkafighter/cb2000-linux/releases/latest), then extract and run the installer:

```bash
tar -xzf cb2000-linux-v*-x86_64.tar.gz
cd cb2000-linux-v*-x86_64
sudo ./packaging/install.sh
```

#### Build from Source

```bash
cargo build --release --workspace
chmod +x packaging/install.sh
sudo ./packaging/install.sh
```

---

## Enable PAM Authentication & Enroll (Both Options)

- **CachyOS / Arch Linux (KDE Plasma / GNOME / `sudo`)**:
  Add `auth sufficient pam_fprintd.so` near the top of:
  - `/etc/pam.d/system-local-login` (or `/etc/pam.d/sddm` / `/etc/pam.d/kde`)
  - `/etc/pam.d/sudo`
  - `/etc/pam.d/polkit-1`

- **Ubuntu (GNOME / KDE / `sudo`)**:
  ```bash
  sudo pam-auth-update
  ```
  Enable **Fingerprint authentication** and select **OK**.

- **Enroll & Verify**:
  - **KDE Plasma**: *System Settings → Users → Your User → Configure Fingerprint Authentication*
  - **GNOME**: *Settings → System → Users → Fingerprint Login*
  - **CLI**:
    ```bash
    fprintd-enroll
    fprintd-verify
    ```

## Clean-Room Notice & License

This codebase was written cleanly from scratch in Rust from an independent hardware protocol specification ([docs/PROTOCOL.md](docs/PROTOCOL.md)). It contains zero vendor code, firmware blobs, or proprietary assets.

Licensed under the [MIT License](LICENSE).
