//! Clean-room CB2000 Match-on-Chip USB protocol driver.

pub mod transport;
pub mod types;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cb2000_sdcp::{
    AttestationPolicy, ConnectResponse, DeviceAttestation, SdcpClientHandshake, SdcpSession,
    SDCP_DIGEST_LEN,
};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::transport::UsbTransport;
use crate::types::{
    CaptureEvent, CapturePurpose, CmdDirection, DeviceCapabilities, DuplicateInfo,
    EnrollSampleOutcome, IdentifyOutcome, Opcode, ProtoError, ProtocolVersion, SlotRecord,
    ACCEPT_SAMPLE_RESULT_LEN, CAPTURE_STATUS_LEN, CHECK_DUP_RESULT_LEN, CMD_STATUS_TRAILER_LEN,
    DEFAULT_ENROLL_STAGES, DEVICE_PARAMS_LEN, IDENTIFY_RESULT_LEN, MAX_SLOTS,
    SDCP_CONNECT_RESP_LEN, SLOT_ENTRY_V1_LEN, SLOT_ENTRY_V2_LEN,
};

/// Poll interval when waiting for a finger capture completion.
const CAPTURE_POLL_INTERVAL: Duration = Duration::from_millis(40);

/// Build the 12-byte CB2000 bulk command header.
pub fn build_cmd_header(
    dir: CmdDirection,
    opcode: Opcode,
    param0: u8,
    param1: u8,
    offset: u32,
    data_len: u16,
) -> [u8; 12] {
    let mut hdr = [0u8; 12];
    hdr[0] = dir as u8;
    hdr[1] = opcode as u8;
    hdr[2] = param0;
    hdr[3] = param1;
    hdr[6..10].copy_from_slice(&offset.to_le_bytes());
    hdr[10..12].copy_from_slice(&data_len.to_le_bytes());
    hdr
}

/// Derive a deterministic 16-byte Linux-specific host UUID for V2 multi-OS partition isolation.
///
/// Domain-separated from the raw SMBIOS UUID used by Windows so dual-boot Linux and Windows
/// enrollments reside in independent partitions on the sensor.
pub fn derive_linux_host_uuid() -> [u8; 16] {
    let source = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .or_else(|_| std::fs::read_to_string("/sys/class/dmi/id/product_uuid"))
        .unwrap_or_else(|_| "cb2000-linux-fallback-host".to_string());

    let mut hasher = Sha256::new();
    hasher.update(b"cb2000-linux-partition-v1\0");
    hasher.update(source.trim().as_bytes());
    let digest = hasher.finalize();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid
}

/// Authenticated driver handle for a CB2000 Match-on-Chip sensor.
///
/// Enforces mandatory SDCP session establishment on open (no plaintext fallback).
pub struct Cb2000Device<T: UsbTransport> {
    transport: T,
    capabilities: DeviceCapabilities,
    session: SdcpSession,
    attestation: DeviceAttestation,
    host_uuid: [u8; 16],
    partition_id: u8,
}

impl<T: UsbTransport> Cb2000Device<T> {
    /// Initialize the sensor, negotiate protocol version, establish a mandatory SDCP session,
    /// and resolve this host's V2 partition ID.
    pub async fn open(
        transport: T,
        policy: &AttestationPolicy,
        host_uuid: [u8; 16],
    ) -> Result<Self, ProtoError> {
        let capabilities = Self::probe_capabilities(&transport).await?;
        info!(
            protocol = ?capabilities.protocol,
            enroll_stages = capabilities.enroll_stages,
            max_slots = capabilities.max_slots,
            finger_up_poll = capabilities.supports_finger_up_poll,
            ctrl_0d = %hex::encode(capabilities.info_0d),
            "Probed CB2000 capabilities"
        );

        let (session, attestation) = Self::sdcp_connect(&transport, policy).await?;
        info!(
            subject = %attestation.model_cert_subject,
            cert_sha256 = %hex::encode(attestation.model_cert_sha256),
            fw_hash = %hex::encode(attestation.firmware_hash),
            "SDCP session established and device attestation verified"
        );

        let mut dev = Self {
            transport,
            capabilities,
            session,
            attestation,
            host_uuid,
            partition_id: 0,
        };

        if dev.capabilities.protocol == ProtocolVersion::V2 {
            dev.partition_id = dev.resolve_partition_id().await?;
            info!(
                partition_id = dev.partition_id,
                host_uuid = %hex::encode(dev.host_uuid),
                "Resolved V2 multi-OS partition ID"
            );
        }

        Ok(dev)
    }

    pub fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }

    pub fn attestation(&self) -> &DeviceAttestation {
        &self.attestation
    }

    pub fn partition_id(&self) -> u8 {
        self.partition_id
    }

    pub fn host_uuid(&self) -> [u8; 16] {
        self.host_uuid
    }

    /// Perform an SDCP Reconnect challenge-response to prove session liveness.
    pub async fn sdcp_reconnect(&self) -> Result<(), ProtoError> {
        let host_random = SdcpSession::fresh_nonce();
        let req = SdcpSession::build_reconnect_request(&host_random);
        self.cmd_data_out(Opcode::SdcpReconnectReq, 0, 0, &req)
            .await?;

        // Reconnect response is length-prefixed (2 + 32 = 34 bytes) or 32 bytes.
        let resp = self
            .cmd_data_in(Opcode::SdcpReconnectResp, 0, 0, 34)
            .await?;
        let mac: [u8; SDCP_DIGEST_LEN] = if resp.len() == 34
            && u16::from_le_bytes([resp[0], resp[1]]) as usize == SDCP_DIGEST_LEN
        {
            resp[2..34]
                .try_into()
                .map_err(|_| ProtoError::MalformedData("reconnect mac slice"))?
        } else {
            return Err(ProtoError::MalformedData("unexpected reconnect response format"));
        };

        self.session.verify_reconnect(&host_random, &mac)?;
        Ok(())
    }

    /// Enumerate all template slots on the sensor.
    pub async fn enumerate_slots(&self) -> Result<Vec<SlotRecord>, ProtoError> {
        let entry_len = match self.capabilities.protocol {
            ProtocolVersion::V2 => SLOT_ENTRY_V2_LEN,
            ProtocolVersion::V1 => SLOT_ENTRY_V1_LEN,
        };
        let max_slots = self.capabilities.max_slots;
        let total_len = u16::try_from(max_slots * entry_len)
            .map_err(|_| ProtoError::MalformedData("slot table length exceeds u16"))?;
        let buf = self
            .cmd_data_in(Opcode::EnumerateSlots, 0, 0, total_len)
            .await?;

        let mut records = Vec::with_capacity(max_slots);
        for idx in 0..max_slots {
            let chunk = &buf[idx * entry_len..(idx + 1) * entry_len];
            let valid = chunk[0] == 1;
            let raw_slot_id = chunk[1];
            let sub_factor = chunk[2];
            let enrollment_id: [u8; SDCP_DIGEST_LEN] = chunk[3..35]
                .try_into()
                .map_err(|_| ProtoError::MalformedData("slot enrollment_id"))?;

            let (partition_id, host_uuid) = if self.capabilities.protocol == ProtocolVersion::V2 {
                let pid = chunk[35];
                let uuid: [u8; 16] = chunk[36..52]
                    .try_into()
                    .map_err(|_| ProtoError::MalformedData("slot host_uuid"))?;
                (Some(pid), Some(uuid))
            } else {
                (None, None)
            };

            records.push(SlotRecord {
                slot_index: idx as u8,
                valid,
                raw_slot_id,
                sub_factor,
                enrollment_id,
                partition_id,
                host_uuid,
            });
        }

        Ok(records)
    }

    /// Return only the occupied slots belonging to this Linux host's partition.
    pub async fn list_owned_slots(&self) -> Result<Vec<SlotRecord>, ProtoError> {
        let all = self.enumerate_slots().await?;
        Ok(all
            .into_iter()
            .filter(|s| s.valid && self.is_owned_slot(s))
            .collect())
    }

    /// Check whether a slot record belongs to this Linux host's partition.
    pub fn is_owned_slot(&self, slot: &SlotRecord) -> bool {
        match self.capabilities.protocol {
            ProtocolVersion::V1 => true,
            ProtocolVersion::V2 => {
                slot.partition_id == Some(self.partition_id)
                    && slot.host_uuid == Some(self.host_uuid)
            }
        }
    }

    /// Wait for the user to place a finger on the sensor, polling status until captured,
    /// cancelled, or timed out.
    pub async fn wait_for_capture<F>(
        &self,
        purpose: CapturePurpose,
        cancel: Arc<AtomicBool>,
        max_wait: Option<Duration>,
        mut on_event: F,
    ) -> Result<(), ProtoError>
    where
        F: FnMut(CaptureEvent),
    {
        let start = Instant::now();
        self.cmd_no_data(Opcode::StartCapture, purpose as u8, 0)
            .await?;

        loop {
            if cancel.load(Ordering::SeqCst) {
                let _ = self.cancel_capture(purpose).await;
                return Err(ProtoError::Cancelled);
            }
            if let Some(limit) = max_wait {
                if start.elapsed() >= limit {
                    let _ = self.cancel_capture(purpose).await;
                    return Err(ProtoError::CaptureTimeout);
                }
            }

            let status = self
                .cmd_data_in(
                    Opcode::GetCaptureStatus,
                    purpose as u8,
                    0,
                    CAPTURE_STATUS_LEN as u16,
                )
                .await?;

            match status[0] {
                0x00 => {
                    debug!(?purpose, "Finger capture complete");
                    return Ok(());
                }
                0x02 => {
                    debug!(?purpose, "Touch rejected by sensor; restarting capture");
                    on_event(CaptureEvent::RetryNeeded);
                    self.cmd_no_data(Opcode::StartCapture, purpose as u8, 0)
                        .await?;
                }
                0x01 | 0x03 => {
                    // 0x01 = waiting for finger, 0x03 = finger detected / capturing in progress.
                }
                other => {
                    warn!(?purpose, status_byte = other, "Unexpected capture status; retrying");
                    on_event(CaptureEvent::RetryNeeded);
                    self.cmd_no_data(Opcode::StartCapture, purpose as u8, 0)
                        .await?;
                }
            }

            sleep(CAPTURE_POLL_INTERVAL).await;
        }
    }

    /// Abort an in-progress finger capture.
    pub async fn cancel_capture(&self, purpose: CapturePurpose) -> Result<(), ProtoError> {
        self.cmd_no_data(Opcode::CancelCapture, purpose as u8, 0)
            .await
    }

    /// Wait until the sensor reports no finger present (`GetCaptureStatus` returns `0x01`),
    /// when supported by firmware (`info_0d[1] & 0x08 != 0`).
    pub async fn wait_for_finger_up(
        &self,
        purpose: CapturePurpose,
        cancel: Arc<AtomicBool>,
        max_wait: Option<Duration>,
    ) -> Result<(), ProtoError> {
        if !self.capabilities.supports_finger_up_poll {
            return Ok(());
        }

        let start = Instant::now();
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(ProtoError::Cancelled);
            }
            if let Some(limit) = max_wait {
                if start.elapsed() >= limit {
                    return Err(ProtoError::CaptureTimeout);
                }
            }

            let status = self
                .cmd_data_in(
                    Opcode::GetCaptureStatus,
                    purpose as u8,
                    0,
                    CAPTURE_STATUS_LEN as u16,
                )
                .await?;

            if status[0] == 0x01 {
                debug!(?purpose, "Finger lifted from sensor");
                return Ok(());
            }

            sleep(CAPTURE_POLL_INTERVAL).await;
        }
    }

    /// Begin an SDCP-authorized enrollment session targeting the first free slot
    /// and return the 32-byte device nonce.
    pub async fn enroll_begin(&self) -> Result<[u8; SDCP_DIGEST_LEN], ProtoError> {
        let slots = self.enumerate_slots().await?;
        let free_slot_index = slots
            .iter()
            .find(|s| !s.valid)
            .map(|s| s.slot_index)
            .ok_or(ProtoError::SlotsFull(self.capabilities.max_slots))?;
        let data = self
            .cmd_data_in(
                Opcode::EnrollBegin,
                free_slot_index,
                0,
                SDCP_DIGEST_LEN as u16,
            )
            .await?;
        data.try_into()
            .map_err(|_| ProtoError::MalformedData("enroll_begin nonce length"))
    }

    /// Process a captured finger sample into the active enrollment template.
    pub async fn enroll_accept_sample(&self) -> Result<EnrollSampleOutcome, ProtoError> {
        let data = self
            .cmd_data_in_allow_device_status(
                Opcode::AcceptEnrollSample,
                CapturePurpose::Enroll as u8,
                0,
                ACCEPT_SAMPLE_RESULT_LEN as u16,
            )
            .await?;
        let status_code = data[0];
        let metadata: [u8; 8] = data[1..9]
            .try_into()
            .map_err(|_| ProtoError::MalformedData("accept sample metadata"))?;
        Ok(EnrollSampleOutcome {
            status_code,
            accepted: status_code == 0x00,
            metadata,
        })
    }

    /// Check if the currently captured enrollment matches an already enrolled template.
    pub async fn check_duplicate(&self) -> Result<Option<DuplicateInfo>, ProtoError> {
        let param1 = match self.capabilities.protocol {
            ProtocolVersion::V2 => self.partition_id,
            ProtocolVersion::V1 => 0,
        };
        let data = self
            .cmd_data_in_allow_device_status(
                Opcode::CheckDuplicate,
                1,
                param1,
                CHECK_DUP_RESULT_LEN as u16,
            )
            .await?;
        if data[0] == 0x00 {
            let sub_factor = data[1];
            let enrollment_id: [u8; SDCP_DIGEST_LEN] = data[2..34]
                .try_into()
                .map_err(|_| ProtoError::MalformedData("duplicate enrollment_id"))?;
            Ok(Some(DuplicateInfo {
                sub_factor,
                enrollment_id,
            }))
        } else {
            Ok(None)
        }
    }

    /// Commit the completed enrollment using an SDCP Enrollment Authorization MAC (`m_a`),
    /// returning the 32-byte `enrollment_id` (`m_a`).
    pub async fn enroll_commit(
        &self,
        sub_factor: u8,
        device_enroll_nonce: &[u8; SDCP_DIGEST_LEN],
    ) -> Result<[u8; SDCP_DIGEST_LEN], ProtoError> {
        let m_a = self.session.compute_enroll_mac(device_enroll_nonce)?;

        match self.capabilities.protocol {
            ProtocolVersion::V1 => {
                self.cmd_data_out(Opcode::EnrollCommit, sub_factor, 0, &m_a)
                    .await?;
            }
            ProtocolVersion::V2 => {
                let mut payload = [0u8; SDCP_DIGEST_LEN + 1 + 16];
                payload[..SDCP_DIGEST_LEN].copy_from_slice(&m_a);
                payload[SDCP_DIGEST_LEN] = self.partition_id;
                payload[SDCP_DIGEST_LEN + 1..].copy_from_slice(&self.host_uuid);
                self.cmd_data_out(Opcode::EnrollCommit, sub_factor, 0, &payload)
                    .await?;
            }
        }

        Ok(m_a)
    }

    /// Perform an SDCP-authenticated Match-on-Chip identification against the captured finger.
    ///
    /// Security guarantee: A `Match` result is ONLY returned if the sensor's 32-byte
    /// `AuthorizedIdentity` MAC verifies in constant time against our session `m_k`
    /// and a freshly generated 32-byte CSPRNG challenge nonce.
    pub async fn identify_captured(&self) -> Result<IdentifyOutcome, ProtoError> {
        let host_nonce = SdcpSession::fresh_nonce();
        self.cmd_data_out(Opcode::IdentifyBegin, 0, 0, &host_nonce)
            .await?;

        let (p0, p1) = match self.capabilities.protocol {
            ProtocolVersion::V2 => (self.partition_id, 1),
            ProtocolVersion::V1 => (0, 1),
        };
        let res = self
            .cmd_data_in_allow_device_status(
                Opcode::IdentifyResult,
                p0,
                p1,
                IDENTIFY_RESULT_LEN as u16,
            )
            .await;

        // Always perform post-identify cleanup regardless of match outcome.
        let _ = self.cmd_no_data(Opcode::IdentifyCleanup, 0, 0).await;

        let data = res?;
        match data[0] {
            0x00 => {
                let sub_factor = data[1];
                let enrollment_id: [u8; SDCP_DIGEST_LEN] = data[2..34]
                    .try_into()
                    .map_err(|_| ProtoError::MalformedData("identify enrollment_id"))?;
                let device_mac: [u8; SDCP_DIGEST_LEN] = data[34..66]
                    .try_into()
                    .map_err(|_| ProtoError::MalformedData("identify mac"))?;
                let metadata: [u8; 8] = data[66..74]
                    .try_into()
                    .map_err(|_| ProtoError::MalformedData("identify metadata"))?;

                // Mandatory constant-time SDCP Authorized Identify MAC verification!
                self.session
                    .verify_identify_mac(&host_nonce, &enrollment_id, &device_mac)?;

                Ok(IdentifyOutcome::Match {
                    sub_factor,
                    enrollment_id,
                    metadata,
                })
            }
            0x0b => Ok(IdentifyOutcome::NoMatch),
            other => Ok(IdentifyOutcome::BadCapture { code: other }),
        }
    }

    /// Delete a single template slot belonging to this Linux host's partition.
    ///
    /// Refuses to delete slots belonging to foreign OS partitions (e.g., Windows Hello)
    /// to guarantee dual-boot safety.
    pub async fn delete_owned_slot(&self, slot_index: u8) -> Result<(), ProtoError> {
        if usize::from(slot_index) >= self.capabilities.max_slots {
            return Err(ProtoError::InvalidSlot(slot_index));
        }

        let slots = self.enumerate_slots().await?;
        let slot = &slots[usize::from(slot_index)];
        if slot.valid && !self.is_owned_slot(slot) {
            return Err(ProtoError::ForeignPartitionSlot { slot: slot_index });
        }

        self.cmd_no_data(Opcode::DeleteSlot, slot_index, 0).await
    }

    /// Delete all template slots owned by this Linux host's partition (preserving other OS slots).
    pub async fn delete_all_owned_slots(&self) -> Result<usize, ProtoError> {
        let owned = self.list_owned_slots().await?;
        let mut deleted = 0usize;
        for slot in owned {
            self.cmd_no_data(Opcode::DeleteSlot, slot.slot_index, 0)
                .await?;
            deleted += 1;
        }
        Ok(deleted)
    }

    async fn probe_capabilities(transport: &T) -> Result<DeviceCapabilities, ProtoError> {
        let read_ctrl = |w_value: u16| async move {
            let v = transport.control_in(0x07, w_value, 0x0000, 8).await?;
            let arr: [u8; 8] = v
                .try_into()
                .map_err(|_| ProtoError::MalformedData("control_in 0x07 did not return 8 bytes"))?;
            Ok::<[u8; 8], ProtoError>(arr)
        };

        let info_08 = read_ctrl(0x0008).await?;
        let info_0a = read_ctrl(0x000a).await?;
        let info_0b = read_ctrl(0x000b).await?;
        let info_0c = read_ctrl(0x000c).await?;
        let info_0d = read_ctrl(0x000d).await?;

        let protocol = if (info_0d[0] & 0x01) != 0 {
            ProtocolVersion::V2
        } else {
            ProtocolVersion::V1
        };
        let supports_finger_up_poll = (info_0d[1] & 0x08) != 0;

        let (enroll_stages, max_slots) = match Self::raw_cmd_data_in(
            transport,
            Opcode::GetDeviceParams,
            0,
            0,
            DEVICE_PARAMS_LEN as u16,
        )
        .await
        {
            Ok(params) if params.len() >= DEVICE_PARAMS_LEN => {
                let stages = if params[0] >= 2 {
                    u32::from(params[0] - 1)
                } else {
                    DEFAULT_ENROLL_STAGES
                };
                let slots = if (1..=64).contains(&params[1]) {
                    usize::from(params[1])
                } else {
                    MAX_SLOTS
                };
                (stages, slots)
            }
            Ok(_) => {
                warn!("GetDeviceParams returned truncated payload; falling back to defaults");
                (DEFAULT_ENROLL_STAGES, MAX_SLOTS)
            }
            Err(e) => {
                warn!(error = %e, "GetDeviceParams failed; falling back to defaults");
                (DEFAULT_ENROLL_STAGES, MAX_SLOTS)
            }
        };

        Ok(DeviceCapabilities {
            protocol,
            enroll_stages,
            max_slots,
            supports_finger_up_poll,
            info_08,
            info_0a,
            info_0b,
            info_0c,
            info_0d,
        })
    }

    async fn sdcp_connect(
        transport: &T,
        policy: &AttestationPolicy,
    ) -> Result<(SdcpSession, DeviceAttestation), ProtoError> {
        let handshake = SdcpClientHandshake::new()?;
        let req_wire = handshake.to_wire_request();

        Self::raw_cmd_data_out(transport, Opcode::SdcpConnectReq, 0, 0, &req_wire).await?;
        let resp_wire = Self::raw_cmd_data_in(
            transport,
            Opcode::SdcpConnectResp,
            0,
            0,
            SDCP_CONNECT_RESP_LEN as u16,
        )
        .await?;

        let response = ConnectResponse::from_wire(&resp_wire)?;
        let (session, attestation) = handshake.complete(&response, policy)?;
        Ok((session, attestation))
    }

    async fn resolve_partition_id(&self) -> Result<u8, ProtoError> {
        let slots = self.enumerate_slots().await?;
        let mut used_partitions = [false; 256];

        for slot in &slots {
            if !slot.valid {
                continue;
            }
            if let (Some(pid), Some(uuid)) = (slot.partition_id, slot.host_uuid) {
                if uuid == self.host_uuid {
                    return Ok(pid);
                }
                used_partitions[usize::from(pid)] = true;
            }
        }

        // Allocate the lowest free partition ID (preferring non-zero if slot 0 is taken by Windows).
        for pid in 0u8..=254 {
            if !used_partitions[usize::from(pid)] {
                return Ok(pid);
            }
        }
        Err(ProtoError::NoFreePartition)
    }

    async fn cmd_no_data(&self, opcode: Opcode, p0: u8, p1: u8) -> Result<(), ProtoError> {
        let hdr = build_cmd_header(CmdDirection::NoData, opcode, p0, p1, 0, 0);
        self.transport.bulk_out(&hdr).await?;
        Self::read_and_check_status(&self.transport, opcode, false).await
    }

    async fn cmd_data_out(
        &self,
        opcode: Opcode,
        p0: u8,
        p1: u8,
        payload: &[u8],
    ) -> Result<(), ProtoError> {
        Self::raw_cmd_data_out(&self.transport, opcode, p0, p1, payload).await
    }

    async fn cmd_data_in(
        &self,
        opcode: Opcode,
        p0: u8,
        p1: u8,
        len: u16,
    ) -> Result<Vec<u8>, ProtoError> {
        Self::raw_cmd_data_in(&self.transport, opcode, p0, p1, len).await
    }

    async fn cmd_data_in_allow_device_status(
        &self,
        opcode: Opcode,
        p0: u8,
        p1: u8,
        len: u16,
    ) -> Result<Vec<u8>, ProtoError> {
        Self::raw_cmd_data_in_inner(&self.transport, opcode, p0, p1, len, true).await
    }

    async fn raw_cmd_data_out(
        transport: &T,
        opcode: Opcode,
        p0: u8,
        p1: u8,
        payload: &[u8],
    ) -> Result<(), ProtoError> {
        let len_u16 = u16::try_from(payload.len())
            .map_err(|_| ProtoError::MalformedData("outgoing payload exceeds u16"))?;
        let hdr = build_cmd_header(CmdDirection::DataOut, opcode, p0, p1, 0, len_u16);
        transport.bulk_out(&hdr).await?;
        transport.bulk_out(payload).await?;
        Self::read_and_check_status(transport, opcode, false).await
    }

    async fn raw_cmd_data_in(
        transport: &T,
        opcode: Opcode,
        p0: u8,
        p1: u8,
        len: u16,
    ) -> Result<Vec<u8>, ProtoError> {
        Self::raw_cmd_data_in_inner(transport, opcode, p0, p1, len, false).await
    }

    async fn raw_cmd_data_in_inner(
        transport: &T,
        opcode: Opcode,
        p0: u8,
        p1: u8,
        len: u16,
        allow_nonzero_status: bool,
    ) -> Result<Vec<u8>, ProtoError> {
        let hdr = build_cmd_header(CmdDirection::DataIn, opcode, p0, p1, 0, len);
        transport.bulk_out(&hdr).await?;
        let data = transport.bulk_in(usize::from(len)).await?;
        Self::read_and_check_status(transport, opcode, allow_nonzero_status).await?;
        Ok(data)
    }

    async fn read_and_check_status(
        transport: &T,
        opcode: Opcode,
        allow_nonzero_status: bool,
    ) -> Result<(), ProtoError> {
        let trailer = transport.bulk_in(CMD_STATUS_TRAILER_LEN).await?;
        let status = trailer[0];
        let detail = u32::from_le_bytes([trailer[1], trailer[2], trailer[3], trailer[4]]);
        if status != 0 {
            if allow_nonzero_status {
                debug!(
                    opcode = opcode as u8,
                    status,
                    detail,
                    "Command returned non-zero status trailer; inspecting payload status byte"
                );
            } else {
                return Err(ProtoError::DeviceStatus {
                    opcode: opcode as u8,
                    status,
                    detail,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{BoxFuture, TransportError};
    use cb2000_sdcp::{kbkdf_counter_hmac_sha256, sdcp_mac};
    use p256::ecdh::EphemeralSecret;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::PublicKey;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Full stateful software emulator of a CB2000 V2 Match-on-Chip sensor for unit tests.
    struct MockCb2000 {
        model_sk: SigningKey,
        model_cert_der: Vec<u8>,
        state: Mutex<MockState>,
    }

    struct MockState {
        pending_hdr: Option<[u8; 12]>,
        in_queue: VecDeque<Vec<u8>>,
        mac_key: [u8; 32],
        enroll_nonce: [u8; 32],
        identify_nonce: [u8; 32],
        slots: Vec<MockSlot>,
        poll_count: u8,
        status_overrides: VecDeque<u8>,
        reject_next_enroll_sample: bool,
        finger_up_poll: bool,
        tamper_identify_mac: bool,
    }

    #[derive(Clone)]
    struct MockSlot {
        valid: bool,
        sub_factor: u8,
        id: [u8; 32],
        pid: u8,
        uuid: [u8; 16],
    }

    fn test_cert(sk: &SigningKey) -> Vec<u8> {
        use der::asn1::BitString;
        use der::Encode;
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::{Time, Validity};
        use x509_cert::{Certificate, TbsCertificate};

        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let spki_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(
                der::Any::encode_from(&ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")).unwrap(),
            ),
        };
        let pub_bytes = sk.verifying_key().to_encoded_point(false);
        let tbs = TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: sig_alg.clone(),
            issuer: "CN=Mock CB2000".parse::<Name>().unwrap(),
            validity: Validity {
                not_before: Time::UtcTime(
                    der::asn1::UtcTime::from_unix_duration(Duration::from_secs(1_700_000_000))
                        .unwrap(),
                ),
                not_after: Time::UtcTime(
                    der::asn1::UtcTime::from_unix_duration(Duration::from_secs(1_900_000_000))
                        .unwrap(),
                ),
            },
            subject: "CN=Mock CB2000".parse::<Name>().unwrap(),
            subject_public_key_info: SubjectPublicKeyInfoOwned {
                algorithm: spki_alg,
                subject_public_key: BitString::from_bytes(pub_bytes.as_bytes()).unwrap(),
            },
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let tbs_der = tbs.to_der().unwrap();
        let sig: Signature = sk.sign_prehash(&Sha256::digest(&tbs_der)).unwrap();
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
        };
        cert.to_der().unwrap()
    }

    impl MockCb2000 {
        fn new(tamper_identify_mac: bool) -> Self {
            let mut rng = rand_core::OsRng;
            let model_sk = SigningKey::random(&mut rng);
            let model_cert_der = test_cert(&model_sk);
            // Pre-populate slot 0 with a "Windows" enrollment on partition 0 to test dual-boot safety!
            let mut slots = vec![
                MockSlot {
                    valid: false,
                    sub_factor: 0,
                    id: [0u8; 32],
                    pid: 0,
                    uuid: [0u8; 16],
                };
                MAX_SLOTS
            ];
            slots[0] = MockSlot {
                valid: true,
                sub_factor: 1,
                id: [0xEE; 32],
                pid: 0,
                uuid: [0x11; 16], // Windows SMBIOS UUID
            };
            Self {
                model_sk,
                model_cert_der,
                state: Mutex::new(MockState {
                    pending_hdr: None,
                    in_queue: VecDeque::new(),
                    mac_key: [0u8; 32],
                    enroll_nonce: [0x55; 32],
                    identify_nonce: [0u8; 32],
                    slots,
                    poll_count: 0,
                    status_overrides: VecDeque::new(),
                    reject_next_enroll_sample: false,
                    finger_up_poll: false,
                    tamper_identify_mac,
                }),
            }
        }

        fn handle_command(&self, hdr: [u8; 12], payload: Option<&[u8]>) {
            let mut st = self.state.lock().unwrap();
            let op = hdr[1];
            let ok_status = vec![0u8; 5];
            let nonzero_status = vec![0x01, 0xef, 0xff, 0xff, 0xff];

            match op {
                0x01 => {
                    // SdcpConnectReq
                    let req = payload.unwrap();
                    let r_h = &req[2..34];
                    let pk_h = PublicKey::from_sec1_bytes(&req[36..101]).unwrap();
                    let mut rng = rand_core::OsRng;
                    let dev_sk = SigningKey::random(&mut rng);
                    let pk_d: [u8; 65] = dev_sk
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .try_into()
                        .unwrap();
                    let fw_sk = EphemeralSecret::random(&mut rng);
                    let pk_f: [u8; 65] = PublicKey::from(&fw_sk)
                        .to_encoded_point(false)
                        .as_bytes()
                        .try_into()
                        .unwrap();
                    let h_f = [0x33u8; 32];
                    let s_m: Signature = self.model_sk.sign_prehash(&Sha256::digest(pk_d)).unwrap();
                    let mut h = Sha256::new();
                    h.update(cb2000_sdcp::SDCP_FW_BINDING_PREFIX);
                    h.update(h_f);
                    h.update(pk_f);
                    let s_d: Signature = dev_sk.sign_prehash(&h.finalize()).unwrap();

                    let mut claim = Vec::new();
                    claim.extend_from_slice(&self.model_cert_der);
                    claim.extend_from_slice(&pk_d);
                    claim.extend_from_slice(&pk_f);
                    claim.extend_from_slice(&h_f);
                    claim.extend_from_slice(&s_m.to_bytes());
                    claim.extend_from_slice(&s_d.to_bytes());

                    let r_d = [0x77u8; 32];
                    let shared = fw_sk.diffie_hellman(&pk_h);
                    let mut ctx = [0u8; 64];
                    ctx[..32].copy_from_slice(r_h);
                    ctx[32..].copy_from_slice(&r_d);
                    let mut ms = [0u8; 32];
                    kbkdf_counter_hmac_sha256(
                        &shared.raw_secret_bytes()[..],
                        b"master secret",
                        &ctx,
                        &mut ms,
                    )
                    .unwrap();
                    let mut app = [0u8; 64];
                    kbkdf_counter_hmac_sha256(&ms, b"application keys", &[], &mut app).unwrap();
                    st.mac_key.copy_from_slice(&app[..32]);

                    let claim_hash: [u8; 32] = Sha256::digest(&claim).into();
                    let mac = sdcp_mac(&st.mac_key, b"connect", &[&claim_hash]).unwrap();

                    let mut resp = vec![0u8; SDCP_CONNECT_RESP_LEN];
                    let mut c = 0usize;
                    resp[c..c + 2].copy_from_slice(&32u16.to_le_bytes());
                    c += 2;
                    resp[c..c + 32].copy_from_slice(&r_d);
                    c += 32;
                    resp[c..c + 2].copy_from_slice(&(claim.len() as u16).to_le_bytes());
                    c += 2;
                    resp[c..c + claim.len()].copy_from_slice(&claim);
                    c += claim.len();
                    resp[c..c + 2].copy_from_slice(&32u16.to_le_bytes());
                    c += 2;
                    resp[c..c + 32].copy_from_slice(&mac);

                    st.in_queue.push_back(ok_status);
                    // Next command will be 0x02 which reads `resp`
                    st.in_queue.push_back(resp);
                }
                0x02 => {
                    // ConnectResp already queued before status; reorder so status follows data
                    st.in_queue.push_back(ok_status);
                }
                0x05 => {
                    st.poll_count = 0;
                    st.in_queue.push_back(ok_status);
                }
                0x06 => {
                    let code = if let Some(override_code) = st.status_overrides.pop_front() {
                        override_code
                    } else {
                        st.poll_count += 1;
                        match st.poll_count {
                            1 => 0x01, // waiting for finger
                            2 => 0x03, // finger detected / capturing
                            _ => 0x00, // complete
                        }
                    };
                    st.in_queue.push_back(vec![code, 0, 0, 0, 0]);
                    st.in_queue.push_back(ok_status);
                }
                0x08 => {
                    let mut resp = vec![0u8; ACCEPT_SAMPLE_RESULT_LEN];
                    let trailer = if st.reject_next_enroll_sample {
                        st.reject_next_enroll_sample = false;
                        resp[0] = 0x0c;
                        nonzero_status
                    } else {
                        ok_status
                    };
                    st.in_queue.push_back(resp);
                    st.in_queue.push_back(trailer);
                }
                0x09 => {
                    assert_eq!(hdr[2], 1, "EnrollBegin must target first free slot index 1");
                    let nonce = st.enroll_nonce.to_vec();
                    st.in_queue.push_back(nonce);
                    st.in_queue.push_back(ok_status);
                }
                0x0A => {
                    let data = payload.unwrap();
                    assert_eq!(data.len(), 49);
                    let m_a: [u8; 32] = data[0..32].try_into().unwrap();
                    let expected = sdcp_mac(&st.mac_key, b"enroll", &[&st.enroll_nonce]).unwrap();
                    assert_eq!(m_a, expected);
                    let pid = data[32];
                    let uuid: [u8; 16] = data[33..49].try_into().unwrap();
                    let free = st.slots.iter_mut().find(|s| !s.valid).unwrap();
                    free.valid = true;
                    free.sub_factor = hdr[2];
                    free.id = m_a;
                    free.pid = pid;
                    free.uuid = uuid;
                    st.in_queue.push_back(ok_status);
                }
                0x0B => {
                    st.identify_nonce.copy_from_slice(payload.unwrap());
                    st.in_queue.push_back(ok_status);
                }
                0x0C => {
                    let pid = hdr[2];
                    assert_eq!(hdr[3], 1, "IdentifyResult param1 must be 1");
                    let mut resp = vec![0u8; IDENTIFY_RESULT_LEN];
                    let trailer = if let Some(slot) =
                        st.slots.iter().find(|s| s.valid && s.pid == pid)
                    {
                        resp[0] = 0x00;
                        resp[1] = slot.sub_factor;
                        resp[2..34].copy_from_slice(&slot.id);
                        let mut mac =
                            sdcp_mac(&st.mac_key, b"identify", &[&st.identify_nonce, &slot.id])
                                .unwrap();
                        if st.tamper_identify_mac {
                            mac[0] ^= 0x80;
                        }
                        resp[34..66].copy_from_slice(&mac);
                        ok_status
                    } else {
                        resp[0] = 0x0b;
                        nonzero_status
                    };
                    st.in_queue.push_back(resp);
                    st.in_queue.push_back(trailer);
                }
                0x0D => {
                    // resp[0] = enroll_stages + 1 (8 stages), resp[1] = max_slots (10)
                    st.in_queue.push_back(vec![9, MAX_SLOTS as u8]);
                    st.in_queue.push_back(ok_status);
                }
                0x0E => {
                    let mut out = Vec::with_capacity(MAX_SLOTS * SLOT_ENTRY_V2_LEN);
                    for (i, s) in st.slots.iter().enumerate() {
                        out.push(u8::from(s.valid));
                        out.push(i as u8);
                        out.push(s.sub_factor);
                        out.extend_from_slice(&s.id);
                        out.push(s.pid);
                        out.extend_from_slice(&s.uuid);
                    }
                    st.in_queue.push_back(out);
                    st.in_queue.push_back(ok_status);
                }
                0x0F => {
                    let idx = usize::from(hdr[2]);
                    st.slots[idx].valid = false;
                    st.in_queue.push_back(ok_status);
                }
                0x10 => {
                    assert_eq!(hdr[2], 1, "CheckDuplicate param0 must be 1 for SDCP mode");
                    assert_eq!(hdr[3], 1, "CheckDuplicate param1 must be Linux partition_id 1");
                    let mut resp = vec![0u8; CHECK_DUP_RESULT_LEN];
                    resp[0] = 0x0b; // not a duplicate
                    st.in_queue.push_back(resp);
                    st.in_queue.push_back(nonzero_status);
                }
                0x15 | 0x07 => {
                    st.in_queue.push_back(ok_status);
                }
                _ => panic!("unhandled mock opcode 0x{op:02x}"),
            }
        }
    }

    impl UsbTransport for MockCb2000 {
        fn control_in<'a>(
            &'a self,
            _request: u8,
            value: u16,
            _index: u16,
            _length: u16,
        ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                let mut v = vec![0u8; 8];
                if value == 0x000d {
                    v[0] = 0x01; // Protocol V2 enabled
                    if self.state.lock().unwrap().finger_up_poll {
                        v[1] = 0x08;
                    }
                }
                Ok(v)
            })
        }

        fn bulk_out<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
            Box::pin(async move {
                let pending = { self.state.lock().unwrap().pending_hdr.take() };
                if let Some(hdr) = pending {
                    self.handle_command(hdr, Some(data));
                } else {
                    let hdr: [u8; 12] = data.try_into().unwrap();
                    if hdr[0] == CmdDirection::DataOut as u8 {
                        self.state.lock().unwrap().pending_hdr = Some(hdr);
                    } else {
                        self.handle_command(hdr, None);
                    }
                }
                Ok(())
            })
        }

        fn bulk_in<'a>(&'a self, length: usize) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
            Box::pin(async move {
                let data = self.state.lock().unwrap().in_queue.pop_front().unwrap();
                assert_eq!(data.len(), length);
                Ok(data)
            })
        }
    }

    #[tokio::test]
    async fn full_v2_enroll_identify_and_dualboot_partition_isolation() {
        let mock = MockCb2000::new(false);
        let linux_uuid = [0x22; 16];
        let dev = Cb2000Device::open(mock, &AttestationPolicy::default(), linux_uuid)
            .await
            .unwrap();

        // Partition 0 is occupied by Windows ([0x11; 16]), so Linux MUST get partition 1!
        assert_eq!(dev.capabilities().protocol, ProtocolVersion::V2);
        assert_eq!(dev.capabilities().enroll_stages, 8);
        assert_eq!(dev.capabilities().max_slots, 10);
        assert!(!dev.capabilities().supports_finger_up_poll);
        assert_eq!(dev.partition_id(), 1);

        // Attempting to delete Windows' slot 0 MUST be rejected!
        assert!(matches!(
            dev.delete_owned_slot(0).await,
            Err(ProtoError::ForeignPartitionSlot { slot: 0 })
        ));

        // Enroll a finger on Linux partition 1
        let nonce = dev.enroll_begin().await.unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut retry_events = 0usize;
        dev.wait_for_capture(CapturePurpose::Enroll, cancel.clone(), None, |_| {
            retry_events += 1;
        })
        .await
        .unwrap();
        assert_eq!(
            retry_events, 0,
            "capture statuses 0x01 and 0x03 must not emit RetryNeeded"
        );
        let sample = dev.enroll_accept_sample().await.unwrap();
        assert!(sample.accepted);
        // When info_0d[1] & 0x08 == 0, wait_for_finger_up returns immediately without polling.
        dev.wait_for_finger_up(CapturePurpose::Enroll, cancel.clone(), Some(Duration::from_secs(2)))
            .await
            .unwrap();
        assert!(dev.check_duplicate().await.unwrap().is_none());
        let enrolled_id = dev.enroll_commit(7, &nonce).await.unwrap();

        // Verify slot list shows 1 owned slot (slot 1) and does NOT expose Windows slot 0
        let owned = dev.list_owned_slots().await.unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].slot_index, 1);
        assert_eq!(owned[0].sub_factor, 7);
        assert_eq!(owned[0].enrollment_id, enrolled_id);

        // Identify verifies MAC and returns our enrolled ID
        dev.wait_for_capture(CapturePurpose::Identify, cancel, None, |_| {})
            .await
            .unwrap();
        match dev.identify_captured().await.unwrap() {
            IdentifyOutcome::Match {
                sub_factor,
                enrollment_id,
                ..
            } => {
                assert_eq!(sub_factor, 7);
                assert_eq!(enrollment_id, enrolled_id);
            }
            other => panic!("expected Match, got {other:?}"),
        }

        // Delete all Linux-owned slots leaves Windows slot 0 untouched
        let deleted = dev.delete_all_owned_slots().await.unwrap();
        assert_eq!(deleted, 1);
        let all_slots = dev.enumerate_slots().await.unwrap();
        assert!(all_slots[0].valid); // Windows slot preserved!
        assert!(!all_slots[1].valid); // Linux slot deleted!
    }

    #[tokio::test]
    async fn tampered_identify_mac_is_rejected() {
        let mock = MockCb2000::new(true);
        let dev = Cb2000Device::open(mock, &AttestationPolicy::default(), [0x22; 16])
            .await
            .unwrap();
        let nonce = dev.enroll_begin().await.unwrap();
        let _ = dev.enroll_commit(1, &nonce).await.unwrap();
        let res = dev.identify_captured().await;
        assert!(matches!(
            res,
            Err(ProtoError::Sdcp(cb2000_sdcp::SdcpError::IdentifyMacMismatch))
        ));
    }

    #[tokio::test]
    async fn rejected_enroll_sample_and_wait_for_finger_up_handle_device_trailer() {
        let mock = MockCb2000::new(false);
        mock.state.lock().unwrap().finger_up_poll = true;
        mock.state.lock().unwrap().reject_next_enroll_sample = true;
        mock.state
            .lock()
            .unwrap()
            .status_overrides
            .extend([0x00, 0x01]);

        let dev = Cb2000Device::open(mock, &AttestationPolicy::default(), [0x22; 16])
            .await
            .unwrap();
        assert!(dev.capabilities().supports_finger_up_poll);

        let sample = dev.enroll_accept_sample().await.unwrap();
        assert!(!sample.accepted);
        assert_eq!(sample.status_code, 0x0c);

        let cancel = Arc::new(AtomicBool::new(false));
        dev.wait_for_finger_up(CapturePurpose::Enroll, cancel, Some(Duration::from_secs(2)))
            .await
            .unwrap();

        let identify = dev.identify_captured().await.unwrap();
        assert_eq!(identify, IdentifyOutcome::NoMatch);
    }
}
