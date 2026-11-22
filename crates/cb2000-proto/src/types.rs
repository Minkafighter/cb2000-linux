//! Wire protocol constants, data structures, and error types for CB2000.

use cb2000_sdcp::{SdcpError, SDCP_DIGEST_LEN};
use thiserror::Error;

use crate::transport::TransportError;

/// Maximum template slots supported on-chip.
pub const MAX_SLOTS: usize = 10;
/// Byte size of one V2 slot table entry returned by opcode `0x0E`.
pub const SLOT_ENTRY_V2_LEN: usize = 52;
/// Byte size of one V1 slot table entry returned by opcode `0x0E`.
pub const SLOT_ENTRY_V1_LEN: usize = 35;
/// Byte size of the SDCP Connect Response buffer read by opcode `0x02`.
pub const SDCP_CONNECT_RESP_LEN: usize = 0x04b6; // 1206 bytes
/// Byte size of the Identify Result payload read by opcode `0x0C`.
pub const IDENTIFY_RESULT_LEN: usize = 0x4a; // 74 bytes
/// Byte size of the CheckDuplicate payload read by opcode `0x10`.
pub const CHECK_DUP_RESULT_LEN: usize = 0x22; // 34 bytes
/// Byte size of the AcceptEnrollSample payload read by opcode `0x08`.
pub const ACCEPT_SAMPLE_RESULT_LEN: usize = 9;
/// Byte size of the CaptureStatus payload read by opcode `0x06`.
pub const CAPTURE_STATUS_LEN: usize = 5;
/// Byte size of the GetDeviceParams payload read by opcode `0x0D`.
pub const DEVICE_PARAMS_LEN: usize = 2;
/// Byte size of the mandatory Bulk IN status trailer on every bulk command.
pub const CMD_STATUS_TRAILER_LEN: usize = 5;

/// Fallback number of enrollment touches expected by the CB2000 on-chip engine
/// if `GetDeviceParams` (`0x45 0x0D`) is unavailable.
pub const DEFAULT_ENROLL_STAGES: u32 = 12;

/// Bulk command direction byte (`cmd[0]`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdDirection {
    NoData = 0x05,
    DataIn = 0x45,
    DataOut = 0x85,
}

/// Bulk command opcode byte (`cmd[1]`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    SdcpConnectReq = 0x01,
    SdcpConnectResp = 0x02,
    SdcpReconnectReq = 0x03,
    SdcpReconnectResp = 0x04,
    StartCapture = 0x05,
    GetCaptureStatus = 0x06,
    CancelCapture = 0x07,
    AcceptEnrollSample = 0x08,
    EnrollBegin = 0x09,
    EnrollCommit = 0x0A,
    IdentifyBegin = 0x0B,
    IdentifyResult = 0x0C,
    GetDeviceParams = 0x0D,
    EnumerateSlots = 0x0E,
    DeleteSlot = 0x0F,
    CheckDuplicate = 0x10,
    IdentifyCleanup = 0x15,
    SetCaptureMode = 0x16,
}

/// Capture purpose passed in `cmd[2]` for StartCapture/GetCaptureStatus/CancelCapture.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePurpose {
    Identify = 0x02,
    Enroll = 0x04,
}

/// Protocol revision negotiated via control transfer `0x07 / wValue=0x000D`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Legacy single-partition format.
    V1,
    /// Multi-host partitioned format (`ctrl_0d[0] & 0x01 != 0`).
    V2,
}

/// Raw 8-byte device capability blocks and runtime parameters read at initialization.
#[derive(Debug, Clone)]
pub struct DeviceCapabilities {
    pub protocol: ProtocolVersion,
    pub enroll_stages: u32,
    pub max_slots: usize,
    pub supports_finger_up_poll: bool,
    pub info_08: [u8; 8],
    pub info_0a: [u8; 8],
    pub info_0b: [u8; 8],
    pub info_0c: [u8; 8],
    pub info_0d: [u8; 8],
}

/// One on-chip template slot entry returned by `EnumerateSlots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRecord {
    pub slot_index: u8,
    pub valid: bool,
    pub raw_slot_id: u8,
    pub sub_factor: u8,
    pub enrollment_id: [u8; SDCP_DIGEST_LEN],
    pub partition_id: Option<u8>,
    pub host_uuid: Option<[u8; 16]>,
}

/// Result of `AcceptEnrollSample` (`0x45 0x08`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollSampleOutcome {
    pub status_code: u8,
    pub accepted: bool,
    pub metadata: [u8; 8],
}

/// Result of `CheckDuplicate` (`0x45 0x10`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateInfo {
    pub sub_factor: u8,
    pub enrollment_id: [u8; SDCP_DIGEST_LEN],
}

/// Result of a cryptographically verified `Identify` (`0x85 0x0B` + `0x45 0x0C`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyOutcome {
    /// Hardware matched AND the SDCP Authorized Identify MAC verified in constant time.
    Match {
        sub_factor: u8,
        enrollment_id: [u8; SDCP_DIGEST_LEN],
        metadata: [u8; 8],
    },
    /// Hardware scanned finger but no enrolled template matched.
    NoMatch,
    /// Capture quality was insufficient; prompt user to retry.
    BadCapture { code: u8 },
}

/// Events emitted while waiting for a finger press during capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureEvent {
    /// Sensor rejected a touch (partial/too fast/etc.) and restarted capture automatically.
    RetryNeeded,
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("USB transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("SDCP cryptographic error: {0}")]
    Sdcp(#[from] SdcpError),

    #[error("device command 0x{opcode:02x} returned non-zero status 0x{status:02x} (detail 0x{detail:08x})")]
    DeviceStatus {
        opcode: u8,
        status: u8,
        detail: u32,
    },

    #[error("operation cancelled")]
    Cancelled,

    #[error("capture timed out waiting for finger")]
    CaptureTimeout,

    #[error("invalid slot index {0} (max {MAX_SLOTS})")]
    InvalidSlot(u8),

    #[error("all {0} template slots on the sensor are occupied")]
    SlotsFull(usize),

    #[error("refusing to delete slot {slot} belonging to another OS partition")]
    ForeignPartitionSlot { slot: u8 },

    #[error("no free partition ID available on sensor")]
    NoFreePartition,

    #[error("protocol parse error: {0}")]
    MalformedData(&'static str),
}
