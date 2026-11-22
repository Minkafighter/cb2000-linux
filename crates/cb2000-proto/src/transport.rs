//! USB transport abstraction and pure-Rust Linux usbfs (`nusb`) implementation.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use nusb::transfer::{ControlIn, ControlType, Recipient, RequestBuffer};
use thiserror::Error;
use tokio::time::timeout;

/// CanvasBio CB2000 USB Vendor ID.
pub const CB2000_VID: u16 = 0x2df0;
/// CanvasBio CB2000 USB Product ID.
pub const CB2000_PID: u16 = 0x0007;

/// USB interface number (Vendor-Specific Class 0xFF).
pub const INTERFACE_NUM: u8 = 0;
/// Bulk OUT endpoint for 12-byte command headers and host-to-device payloads.
pub const EP_BULK_OUT: u8 = 0x01;
/// Bulk IN endpoint for device-to-host payloads and 5-byte status trailers.
pub const EP_BULK_IN: u8 = 0x82;
/// Interrupt IN endpoint for sensor event notifications.
pub const EP_INT_IN: u8 = 0x83;

/// Default USB transfer timeout.
pub const DEFAULT_USB_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("CB2000 fingerprint sensor (2df0:0007) not found on USB bus")]
    DeviceNotFound,

    #[error("permission denied opening USB device (install udev rule 60-cb2000-fingerprint.rules or run as root)")]
    PermissionDenied,

    #[error("USB I/O error: {0}")]
    Io(String),

    #[error("USB transfer timed out after {0:?}")]
    Timeout(Duration),

    #[error("short USB transfer: expected {expected} bytes, got {actual}")]
    ShortTransfer { expected: usize, actual: usize },
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Async USB transport trait allowing both real `nusb` hardware access and deterministic unit tests.
pub trait UsbTransport: Send + Sync {
    fn control_in<'a>(
        &'a self,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;

    fn bulk_out<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>>;

    fn bulk_in<'a>(&'a self, length: usize) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}

/// Pure-Rust Linux USB transport backed by `nusb`.
pub struct NusbTransport {
    interface: nusb::Interface,
    timeout: Duration,
}

impl NusbTransport {
    /// Locate and open the first attached CB2000 (`2df0:0007`) USB sensor.
    pub fn open_default() -> Result<Self, TransportError> {
        Self::open_vid_pid(CB2000_VID, CB2000_PID)
    }

    /// Open a specific VID/PID sensor and claim interface 0.
    pub fn open_vid_pid(vid: u16, pid: u16) -> Result<Self, TransportError> {
        let dev_info = nusb::list_devices()
            .map_err(|e| TransportError::Io(e.to_string()))?
            .find(|d| d.vendor_id() == vid && d.product_id() == pid)
            .ok_or(TransportError::DeviceNotFound)?;

        let device = dev_info.open().map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                TransportError::PermissionDenied
            } else {
                TransportError::Io(e.to_string())
            }
        })?;

        let interface = device
            .claim_interface(INTERFACE_NUM)
            .map_err(|e| TransportError::Io(format!("claim interface {INTERFACE_NUM}: {e}")))?;

        Ok(Self {
            interface,
            timeout: DEFAULT_USB_TIMEOUT,
        })
    }
}

impl UsbTransport for NusbTransport {
    fn control_in<'a>(
        &'a self,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let ctrl = ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Device,
                request,
                value,
                index,
                length,
            };
            let completion = timeout(self.timeout, self.interface.control_in(ctrl))
                .await
                .map_err(|_| TransportError::Timeout(self.timeout))?;
            completion
                .into_result()
                .map_err(|e| TransportError::Io(format!("control_in(0x{request:02x}): {e}")))
        })
    }

    fn bulk_out<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        let payload = data.to_vec();
        let expected = payload.len();
        Box::pin(async move {
            let completion = timeout(self.timeout, self.interface.bulk_out(EP_BULK_OUT, payload))
                .await
                .map_err(|_| TransportError::Timeout(self.timeout))?;
            let actual = completion.data.actual_length();
            completion
                .status
                .map_err(|e| TransportError::Io(format!("bulk_out: {e}")))?;
            if actual != expected {
                return Err(TransportError::ShortTransfer { expected, actual });
            }
            Ok(())
        })
    }

    fn bulk_in<'a>(&'a self, length: usize) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let completion = timeout(
                self.timeout,
                self.interface.bulk_in(EP_BULK_IN, RequestBuffer::new(length)),
            )
            .await
            .map_err(|_| TransportError::Timeout(self.timeout))?;
            let data = completion
                .into_result()
                .map_err(|e| TransportError::Io(format!("bulk_in({length}): {e}")))?;
            if data.len() != length {
                return Err(TransportError::ShortTransfer {
                    expected: length,
                    actual: data.len(),
                });
            }
            Ok(data)
        })
    }
}
