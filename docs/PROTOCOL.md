# CB2000 USB Match-on-Chip & SDCP Protocol Specification (Clean-Room)

This document is an independent, clean-room hardware interoperability specification for the USB Match-on-Chip (MoC) fingerprint reader with USB VID `0x2df0` and PID `0x0007` (found in the Samsung Galaxy Book5 360 and related systems).

## 1. USB Interface & Endpoints

- **Vendor ID / Product ID**: `0x2df0:0x0007`
- **USB Class**: Vendor-Specific (`0xFF`), Interface `0`, Alt Setting `0`
- **Endpoints**:
  - `0x01` — Bulk OUT (max packet size 512 bytes): Command headers and host-to-device payloads.
  - `0x82` — Bulk IN (max packet size 512 bytes): Device-to-host payloads and 5-byte command status trailers.
  - `0x83` — Interrupt IN (max packet size 16 bytes): Asynchronous status notifications.
  - `0x84` — Interrupt IN (max packet size 16 bytes): Auxiliary interrupt notifications.

## 2. Control Transfers (Device Capabilities)

Vendor IN control transfers (`bmRequestType = 0xC0`, `bRequest = 0x07`, `wIndex = 0x0000`, `wLength = 8`) query 8-byte device capability/info descriptors:

| `wValue` | Purpose |
|----------|---------|
| `0x0008` | Device/firmware info block A |
| `0x000A` | Device/firmware info block B |
| `0x000B` | Device/firmware info block C |
| `0x000C` | Device feature flags |
| `0x000D` | Protocol revision & capability flags; **bit 0 (`resp[0] & 0x01`)** selects Multi-Host Partitioning (Protocol V2) when set, or Legacy (Protocol V1) when clear; **bit 3 of `resp[1]` (`resp[1] & 0x08`)** enables inter-stage finger-lift polling via `GetCaptureStatus` (`0x45 0x06` until `0x01`) |

## 3. Bulk Command Framing

Every bulk command begins with a **12-byte little-endian command header** sent on EP `0x01`:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0` | 1 | `direction` | `0x05` = no data phase, `0x45` = data IN (device → host), `0x85` = data OUT (host → device) |
| `1` | 1 | `opcode` | Command opcode |
| `2` | 1 | `param0` | Command-specific parameter (purpose, slot index, sub-factor, or partition ID) |
| `3` | 1 | `param1` | Secondary parameter (`1` / `2` for IdentifyResult, `partition_id` in V2 for CheckDuplicate) |
| `4..6` | 2 | `reserved` | Zero (`0x0000`) |
| `6..10` | 4 | `offset` | Optional 32-bit LE byte offset for chunked transfers (otherwise `0`) |
| `10..12` | 2 | `length` | 16-bit LE byte length of the data phase (`0` for no-data commands) |

### Transfer Phases
1. **Command Phase**: Bulk OUT (`0x01`) — 12-byte header.
2. **Data Phase** (optional):
   - If `direction == 0x85`: Bulk OUT (`0x01`) — `length` bytes.
   - If `direction == 0x45`: Bulk IN (`0x82`) — `length` bytes.
3. **Status Phase** (mandatory): Bulk IN (`0x82`) — 5-byte status trailer:
   - `status[0]`: `0x00` = success; non-zero = command status/error.
   - `status[1..5]`: 32-bit LE device status/error code (e.g. `0xffffffef` = `-17`).
   - **Important**: Opcodes `0x08` (`AcceptEnrollSample`), `0x0C` (`IdentifyResult`), and `0x10` (`CheckDuplicate`) return operation-level status in `data[0]` of their Bulk IN payload and may set `status[0] = 0x01` (with `detail = 0xffffffef`) in the 5-byte trailer on non-matching, rejected-sample, or non-duplicate outcomes. Hosts must read the 5-byte trailer and inspect `data[0]` rather than treating `status[0] != 0` as a USB/transport failure.

## 4. Command Reference

| Dir | Opcode | Name | Data Len | Description |
|-----|--------|------|----------|-------------|
| `0x85` | `0x01` | `SdcpConnectReq` | `101` | `[u16_le(32) \|\| r_h(32) \|\| u16_le(65) \|\| pk_h(65)]` |
| `0x45` | `0x02` | `SdcpConnectResp` | `1206` (`0x4b6`) | `[u16_le(len_rd) \|\| r_d \|\| u16_le(len_claim) \|\| claim \|\| u16_le(len_mac) \|\| mac]` |
| `0x85` | `0x03` | `SdcpReconnectReq` | `34` | `[u16_le(32) \|\| r_h(32)]` |
| `0x45` | `0x04` | `SdcpReconnectResp` | `34` | `[u16_le(32) \|\| mac(32)]` (or raw 32B MAC depending on firmware) |
| `0x05` | `0x05` | `StartCapture` | `0` | `param0` = purpose (`0x02` identify/verify, `0x04` enroll) |
| `0x45` | `0x06` | `GetCaptureStatus` | `5` | `param0` = purpose. `resp[0]`: `0x00` = finger captured, `0x01` = waiting for finger (no finger present), `0x02` = rejected/retry, `0x03` = finger detected / capturing. When `info_0d[1] & 0x08 != 0`, hosts poll until `resp[0] == 0x01` (finger lifted) between enrollment stages before issuing the next `StartCapture` |
| `0x05` | `0x07` | `CancelCapture` | `0` | `param0` = purpose. Aborts an active capture |
| `0x45` | `0x08` | `AcceptEnrollSample` | `9` | `param0` = `0x04`. Processes captured sample into enrollment. `resp[0] == 0x00` accepted; non-zero (e.g. `0x0c` duplicate/reject; trailer may report `0x01 / 0xffffffef`) rejected; `resp[1..9]` metadata |
| `0x45` | `0x09` | `EnrollBegin` | `32` | `param0` = `first_free_slot_index` (`0..max_slots-1`). Begins SDCP enrollment and returns 32-byte device enrollment nonce `n` |
| `0x85` | `0x0A` | `EnrollCommit` | `32` (V1) / `49` (V2) | `param0` = `sub_factor`. Payload: `m_a(32)` in V1, or `m_a(32) \|\| partition_id(1) \|\| host_uuid(16)` in V2 |
| `0x85` | `0x0B` | `IdentifyBegin` | `32` | Sends 32-byte fresh host challenge nonce `n` |
| `0x45` | `0x0C` | `IdentifyResult` | `74` (`0x4a`) | V1: `param0 = 0`, `param1 = 1` (active session) or `2` (lock-screen); V2: `param0 = partition_id`, `param1 = 1` (active session) or `2` (lock-screen). Resp: `[status(1) \|\| sub_factor(1) \|\| id(32) \|\| mac(32) \|\| meta(8)]`. `status`: `0x00` match, `0x0b` no match, else bad capture (trailer may report `0x01 / 0xffffffef` when `status != 0`) |
| `0x45` | `0x0D` | `GetDeviceParams` | `2` | Returns `[enroll_stages + 1, max_slots]` (adapter fallback when `resp[0] < 2` is 12 stages) |
| `0x45` | `0x0E` | `EnumerateSlots` | `slots * 52` (V2) / `slots * 35` (V1) | Reads template slot table (`max_slots`, default `10`). Each 52-byte V2 entry: `[valid(1) \|\| slot_id(1) \|\| sub_factor(1) \|\| enrollment_id(32) \|\| partition_id(1) \|\| host_uuid(16)]`; V1 omits `partition_id` and `host_uuid` |
| `0x05` | `0x0F` | `DeleteSlot` | `0` | `param0` = slot index (`0..max_slots-1`) |
| `0x45` | `0x10` | `CheckDuplicate` | `34` (`0x22`) | `param0 = 0x01` (SDCP active); `param1 = partition_id` (V2) or `0` (V1). Resp: `[is_dup(1, 0=dup) \|\| sub_factor(1) \|\| id(32)]` (trailer may report `0x01 / 0xffffffef` when not a duplicate) |
| `0x05` | `0x15` | `IdentifyCleanup` | `0` | Post-identify cleanup / reset sensor state |
| `0x05` | `0x16` | `SetCaptureMode` | `0` | `param0 = 0x04` optional mode hint |

## 5. SDCP Cryptographic Handshake & Verification

The sensor implements Microsoft's **Secure Device Connection Protocol (SDCP) v1**:

1. **Key Agreement**:
   - Host generates 32-byte random `r_h` and ephemeral NIST P-256 keypair `(sk_h, pk_h)` (`pk_h` encoded as 65-byte SEC1 uncompressed `0x04 || X || Y`).
   - Device returns `r_d` (32 bytes), `claim`, and `connect_mac` (32 bytes).
   - `claim` consists of:
     - `model_cert`: ASN.1 DER X.509 certificate (length parsed from DER header).
     - `pk_d`: 65-byte uncompressed P-256 device static public key.
     - `pk_f`: 65-byte uncompressed P-256 firmware ephemeral public key.
     - `h_f`: 32-byte firmware measurement hash.
     - `s_m`: 64-byte raw ECDSA-P256 `(r || s)` signature by `model_cert` key over `pk_d`.
     - `s_d`: 64-byte raw ECDSA-P256 `(r || s)` signature by `pk_d` over `SHA-256([0xC0, 0x01] || h_f || pk_f)`.
   - Host verifies `s_m` and `s_d` (and validates `model_cert`).
   - Host computes ECDH P-256 shared secret `z = ECDH(sk_h, pk_f)` (32-byte big-endian X coordinate).
2. **Key Derivation (NIST SP 800-108 Counter Mode with HMAC-SHA256)**:
   - `KBKDF(key, label, context, L_bytes)`:
     For counter `i = 1..=ceil(L_bytes / 32)`:
     `K(i) = HMAC-SHA256(key, u32_be(i) || label || 0x00 || context || u32_be(L_bytes * 8))`
   - `master_secret (32B) = KBKDF(z, "master secret", r_h || r_d, 32)`
   - `m_k (32B) || s_k (32B) = KBKDF(master_secret, "application keys", "", 64)`
3. **Message Authentication Codes (Constant-Time Verified)**:
   - **Connect**: `HMAC-SHA256(m_k, "connect\0" || SHA256(claim))`
   - **Reconnect**: `HMAC-SHA256(m_k, "reconnect\0" || r_h)`
   - **Enroll Commit (`m_a`)**: `HMAC-SHA256(m_k, "enroll\0" || device_enroll_nonce)`
   - **Authorized Identify**: `HMAC-SHA256(m_k, "identify\0" || host_identify_nonce || matched_enrollment_id)`

## 6. Multi-OS Partition Isolation (Dual-Boot Safety)

When Protocol V2 (`ctrl(0x07, 0x000d)[0] & 1 == 1`) is active, each template slot records a 1-byte `partition_id` and a 16-byte `host_uuid`.
The Linux driver derives a deterministic Linux-specific 16-byte UUID (domain-separated from the raw SMBIOS UUID used by Windows), queries `EnumerateSlots`, and selects an existing matching `partition_id` or allocates a free `partition_id` that does not collide with Windows partitions. This prevents Linux and Windows enrollments from interfering with each other on dual-boot systems.
