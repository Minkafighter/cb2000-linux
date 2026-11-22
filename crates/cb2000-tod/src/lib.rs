//! C ABI staticlib bridge exposing the clean-room Rust CB2000 SDCP driver
//! (`cb2000-sdcp` + `cb2000-proto`) to a thin `libfprint-2-tod-1` C plugin.
//!
//! All `unsafe` code in this workspace is isolated to this FFI boundary crate.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cb2000_proto::transport::{BoxFuture, TransportError, UsbTransport};
use cb2000_proto::types::{
    CaptureEvent, CapturePurpose, IdentifyOutcome, ProtoError, ProtocolVersion,
};
use cb2000_proto::{derive_linux_host_uuid, Cb2000Device};
use cb2000_sdcp::{AttestationPolicy, SDCP_DIGEST_LEN};
use subtle::ConstantTimeEq;
use tokio::runtime::{Builder, Runtime};
use tracing::error;

pub const CB2000_TOD_OK: i32 = 0;
pub const CB2000_TOD_ERR_INVALID_ARG: i32 = -1;
pub const CB2000_TOD_ERR_TRANSPORT: i32 = -2;
pub const CB2000_TOD_ERR_SDCP: i32 = -3;
pub const CB2000_TOD_ERR_PROTOCOL: i32 = -4;
pub const CB2000_TOD_ERR_CANCELLED: i32 = -5;
pub const CB2000_TOD_ERR_TIMEOUT: i32 = -6;
pub const CB2000_TOD_ERR_SLOTS_FULL: i32 = -7;
pub const CB2000_TOD_ERR_DUPLICATE: i32 = -8;
pub const CB2000_TOD_ERR_NOT_FOUND: i32 = -9;
pub const CB2000_TOD_ERR_NO_MATCH: i32 = -10;
pub const CB2000_TOD_ERR_BAD_CAPTURE: i32 = -11;
pub const CB2000_TOD_ERR_INTERNAL: i32 = -12;

pub const CB2000_TOD_EVENT_FINGER_NEEDED: u32 = 1;
pub const CB2000_TOD_EVENT_FINGER_PRESENT: u32 = 2;
pub const CB2000_TOD_EVENT_FINGER_REMOVED: u32 = 3;
pub const CB2000_TOD_EVENT_STAGE_PASSED: u32 = 4;
pub const CB2000_TOD_EVENT_RETRY_SCAN: u32 = 5;

const CAPTURE_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const FINGER_UP_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

type ControlInFn = unsafe extern "C" fn(*mut c_void, u8, u16, u16, *mut u8, usize) -> i32;
type BulkOutFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;
type BulkInFn = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32;
pub type Cb2000ProgressCb = Option<unsafe extern "C" fn(u32, u32, *mut c_void)>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Cb2000UsbVtable {
    pub control_in: Option<ControlInFn>,
    pub bulk_out: Option<BulkOutFn>,
    pub bulk_in: Option<BulkInFn>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cb2000TodCaps {
    pub protocol_version: u8,
    pub partition_id: u8,
    pub supports_finger_up_poll: u8,
    pub _reserved: u8,
    pub enroll_stages: u32,
    pub max_slots: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cb2000TodSlot {
    pub slot_index: u8,
    pub sub_factor: u8,
    pub enrollment_id: [u8; SDCP_DIGEST_LEN],
}

#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);

// SAFETY: `libfprint` serializes device actions on a single opened `FpDevice`
// and `Cb2000TodHandle` holds `op_lock` across all USB operations using `usb_ctx`.
unsafe impl Send for SendPtr {}
// SAFETY: Same synchronization guarantee as `Send` via `op_lock`.
unsafe impl Sync for SendPtr {}

struct FfiUsbTransport {
    control_in: ControlInFn,
    bulk_out: BulkOutFn,
    bulk_in: BulkInFn,
    usb_ctx: SendPtr,
}

impl UsbTransport for FfiUsbTransport {
    fn control_in<'a>(
        &'a self,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let mut buf = vec![0u8; usize::from(length)];
            // SAFETY: `buf` is valid for `buf.len()` writable bytes and `control_in`
            // is invoked synchronously under `op_lock`.
            let rc = unsafe {
                (self.control_in)(
                    self.usb_ctx.0,
                    request,
                    value,
                    index,
                    buf.as_mut_ptr(),
                    buf.len(),
                )
            };
            if rc < 0 {
                return Err(TransportError::Io(format!("GUsb control_in failed ({rc})")));
            }
            let actual = usize::try_from(rc).unwrap_or(0).min(buf.len());
            buf.truncate(actual);
            Ok(buf)
        })
    }

    fn bulk_out<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            // SAFETY: `data` is valid for `data.len()` readable bytes and `bulk_out`
            // does not retain the pointer past return.
            let rc = unsafe { (self.bulk_out)(self.usb_ctx.0, data.as_ptr(), data.len()) };
            if rc < 0 {
                return Err(TransportError::Io(format!("GUsb bulk_out failed ({rc})")));
            }
            Ok(())
        })
    }

    fn bulk_in<'a>(&'a self, length: usize) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let mut buf = vec![0u8; length];
            // SAFETY: `buf` is valid for `buf.len()` writable bytes and `bulk_in`
            // is invoked synchronously under `op_lock`.
            let rc = unsafe { (self.bulk_in)(self.usb_ctx.0, buf.as_mut_ptr(), buf.len()) };
            if rc < 0 {
                return Err(TransportError::Io(format!("GUsb bulk_in failed ({rc})")));
            }
            let actual = usize::try_from(rc).unwrap_or(0).min(length);
            if actual < length {
                return Err(TransportError::ShortTransfer {
                    expected: length,
                    actual,
                });
            }
            Ok(buf)
        })
    }
}

/// Opaque handle exposed across the C FFI boundary.
pub struct Cb2000TodHandle {
    rt: Runtime,
    dev: Cb2000Device<FfiUsbTransport>,
    cancel: Arc<AtomicBool>,
    op_lock: Mutex<()>,
    last_error: Mutex<String>,
}

impl Cb2000TodHandle {
    fn set_error(&self, msg: String) {
        let mut guard = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        *guard = msg;
    }

    fn clear_error(&self) {
        let mut guard = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();
    }
}

fn map_proto_error(err: &ProtoError) -> i32 {
    match err {
        ProtoError::Cancelled => CB2000_TOD_ERR_CANCELLED,
        ProtoError::CaptureTimeout => CB2000_TOD_ERR_TIMEOUT,
        ProtoError::Sdcp(_) => CB2000_TOD_ERR_SDCP,
        ProtoError::Transport(TransportError::Timeout(_)) => CB2000_TOD_ERR_TIMEOUT,
        ProtoError::Transport(_) => CB2000_TOD_ERR_TRANSPORT,
        ProtoError::SlotsFull(_) => CB2000_TOD_ERR_SLOTS_FULL,
        _ => CB2000_TOD_ERR_PROTOCOL,
    }
}

fn record_proto_error(handle: &Cb2000TodHandle, err: ProtoError) -> i32 {
    let code = map_proto_error(&err);
    handle.set_error(err.to_string());
    code
}

fn emit_progress(cb: Cb2000ProgressCb, ctx: SendPtr, kind: u32, value: u32) {
    if let Some(func) = cb {
        // SAFETY: `func` and `ctx` are guaranteed valid by the C caller for the
        // duration of the synchronous FFI operation.
        unsafe {
            func(kind, value, ctx.0);
        }
    }
}

/// # Safety
/// Caller must ensure `handle` is either null or a live pointer returned by `cb2000_tod_open`
/// that has not yet been freed by `cb2000_tod_close`.
unsafe fn borrow_handle<'a>(handle: *const Cb2000TodHandle) -> Result<&'a Cb2000TodHandle, i32> {
    if handle.is_null() {
        return Err(CB2000_TOD_ERR_INVALID_ARG);
    }
    // SAFETY: Caller guarantees `handle` points to a valid live `Cb2000TodHandle`.
    Ok(unsafe { &*handle })
}

fn guard_ffi(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(CB2000_TOD_ERR_INTERNAL)
}

/// Open the CB2000 sensor over the caller-supplied USB vtable, verify full SDCP attestation,
/// and return an initialized `Cb2000TodHandle` plus discovered capabilities.
///
/// # Safety
/// `vtable`, `out_handle`, and `out_caps` must be valid aligned pointers. `usb_ctx` is passed
/// verbatim to `vtable` callbacks.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_open(
    vtable: *const Cb2000UsbVtable,
    usb_ctx: *mut c_void,
    out_handle: *mut *mut Cb2000TodHandle,
    out_caps: *mut Cb2000TodCaps,
) -> i32 {
    guard_ffi(|| {
        if vtable.is_null() || out_handle.is_null() || out_caps.is_null() {
            return CB2000_TOD_ERR_INVALID_ARG;
        }
        // SAFETY: `out_handle` was verified non-null above.
        unsafe {
            *out_handle = ptr::null_mut();
        }

        // SAFETY: `vtable` is verified non-null and points to a valid `Cb2000UsbVtable`.
        let vt = unsafe { *vtable };
        let (Some(control_in), Some(bulk_out), Some(bulk_in)) =
            (vt.control_in, vt.bulk_out, vt.bulk_in)
        else {
            return CB2000_TOD_ERR_INVALID_ARG;
        };

        let rt = match Builder::new_current_thread().enable_time().build() {
            Ok(rt) => rt,
            Err(e) => {
                error!(error = %e, "Failed to construct Tokio runtime for cb2000-tod");
                return CB2000_TOD_ERR_INTERNAL;
            }
        };

        let transport = FfiUsbTransport {
            control_in,
            bulk_out,
            bulk_in,
            usb_ctx: SendPtr(usb_ctx),
        };
        let host_uuid = derive_linux_host_uuid();
        let policy = AttestationPolicy::default();

        let dev = match rt.block_on(Cb2000Device::open(transport, &policy, host_uuid)) {
            Ok(dev) => dev,
            Err(e) => {
                error!(error = %e, "cb2000_tod_open failed");
                return map_proto_error(&e);
            }
        };

        let caps = dev.capabilities();
        let c_caps = Cb2000TodCaps {
            protocol_version: match caps.protocol {
                ProtocolVersion::V1 => 1,
                ProtocolVersion::V2 => 2,
            },
            partition_id: dev.partition_id(),
            supports_finger_up_poll: u8::from(caps.supports_finger_up_poll),
            _reserved: 0,
            enroll_stages: caps.enroll_stages,
            max_slots: u32::try_from(caps.max_slots).unwrap_or(10),
        };

        let boxed = Box::new(Cb2000TodHandle {
            rt,
            dev,
            cancel: Arc::new(AtomicBool::new(false)),
            op_lock: Mutex::new(()),
            last_error: Mutex::new(String::new()),
        });

        // SAFETY: `out_caps` and `out_handle` were verified non-null above.
        unsafe {
            *out_caps = c_caps;
            *out_handle = Box::into_raw(boxed);
        }
        CB2000_TOD_OK
    })
}

/// Close and free a `Cb2000TodHandle`. Safe to call with `NULL`.
///
/// # Safety
/// `handle` must be null or a valid live pointer from `cb2000_tod_open` with no concurrent
/// callers remaining.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_close(handle: *mut Cb2000TodHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Caller transfers exclusive ownership of `handle` at close.
        let boxed = unsafe { Box::from_raw(handle) };
        drop(boxed);
    }));
}

/// Signal an active `cb2000_tod_enroll` or `cb2000_tod_identify` call to cancel cleanly.
///
/// # Safety
/// `handle` must be null or a valid live pointer from `cb2000_tod_open`.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_cancel(handle: *const Cb2000TodHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Only sets an atomic flag while `handle` is live.
        if let Ok(h) = unsafe { borrow_handle(handle) } {
            h.cancel.store(true, Ordering::SeqCst);
        }
    }));
}

enum EnrollOutcome {
    Committed([u8; SDCP_DIGEST_LEN]),
    Duplicate,
}

/// Execute a full SDCP-authenticated enrollment on the chip.
///
/// # Safety
/// `handle` must be valid; `out_enrollment_id` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_enroll(
    handle: *const Cb2000TodHandle,
    sub_factor: u8,
    progress_cb: Cb2000ProgressCb,
    progress_ctx: *mut c_void,
    out_enrollment_id: *mut u8,
) -> i32 {
    guard_ffi(|| {
        if out_enrollment_id.is_null() {
            return CB2000_TOD_ERR_INVALID_ARG;
        }
        // SAFETY: Caller guarantees `handle` is live until `cb2000_tod_close`.
        let h = match unsafe { borrow_handle(handle) } {
            Ok(h) => h,
            Err(code) => return code,
        };

        let _op_guard = h.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        h.clear_error();
        h.cancel.store(false, Ordering::SeqCst);
        let pctx = SendPtr(progress_ctx);

        let res: Result<EnrollOutcome, ProtoError> = h.rt.block_on(async {
            let nonce = h.dev.enroll_begin().await?;
            let total_stages = h.dev.capabilities().enroll_stages;
            let mut completed = 0u32;

            while completed < total_stages {
                emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_FINGER_NEEDED, completed);
                h.dev
                    .wait_for_capture(
                        CapturePurpose::Enroll,
                        h.cancel.clone(),
                        Some(CAPTURE_WAIT_TIMEOUT),
                        |ev| {
                            if ev == CaptureEvent::RetryNeeded {
                                emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_RETRY_SCAN, 0);
                            }
                        },
                    )
                    .await?;

                emit_progress(
                    progress_cb,
                    pctx,
                    CB2000_TOD_EVENT_FINGER_PRESENT,
                    completed,
                );
                let outcome = h.dev.enroll_accept_sample().await?;
                if outcome.accepted {
                    completed += 1;
                    emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_STAGE_PASSED, completed);
                    if completed < total_stages {
                        h.dev
                            .wait_for_finger_up(
                                CapturePurpose::Enroll,
                                h.cancel.clone(),
                                Some(FINGER_UP_WAIT_TIMEOUT),
                            )
                            .await?;
                        emit_progress(
                            progress_cb,
                            pctx,
                            CB2000_TOD_EVENT_FINGER_REMOVED,
                            completed,
                        );
                    }
                } else {
                    emit_progress(
                        progress_cb,
                        pctx,
                        CB2000_TOD_EVENT_RETRY_SCAN,
                        u32::from(outcome.status_code),
                    );
                    h.dev
                        .wait_for_finger_up(
                            CapturePurpose::Enroll,
                            h.cancel.clone(),
                            Some(FINGER_UP_WAIT_TIMEOUT),
                        )
                        .await?;
                    emit_progress(
                        progress_cb,
                        pctx,
                        CB2000_TOD_EVENT_FINGER_REMOVED,
                        completed,
                    );
                }
            }

            if h.dev.check_duplicate().await?.is_some() {
                emit_progress(
                    progress_cb,
                    pctx,
                    CB2000_TOD_EVENT_FINGER_REMOVED,
                    completed,
                );
                return Ok(EnrollOutcome::Duplicate);
            }

            let enrollment_id = h.dev.enroll_commit(sub_factor, &nonce).await?;
            emit_progress(
                progress_cb,
                pctx,
                CB2000_TOD_EVENT_FINGER_REMOVED,
                completed,
            );
            Ok(EnrollOutcome::Committed(enrollment_id))
        });

        match res {
            Ok(EnrollOutcome::Committed(id)) => {
                // SAFETY: `out_enrollment_id` was verified non-null and writable for 32 bytes.
                let out_slice =
                    unsafe { slice::from_raw_parts_mut(out_enrollment_id, SDCP_DIGEST_LEN) };
                out_slice.copy_from_slice(&id);
                CB2000_TOD_OK
            }
            Ok(EnrollOutcome::Duplicate) => {
                h.set_error("enrolled finger duplicates an existing template".to_string());
                CB2000_TOD_ERR_DUPLICATE
            }
            Err(e) => record_proto_error(h, e),
        }
    })
}

/// Capture and match a finger with mandatory constant-time SDCP `AuthorizedIdentity`
/// MAC verification.
///
/// # Safety
/// `handle` must be valid; `out_enrollment_id` must point to 32 writable bytes.
/// `out_sub_factor` and `out_bad_capture_code` may be null if not needed.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_identify(
    handle: *const Cb2000TodHandle,
    progress_cb: Cb2000ProgressCb,
    progress_ctx: *mut c_void,
    out_sub_factor: *mut u8,
    out_enrollment_id: *mut u8,
    out_bad_capture_code: *mut u8,
) -> i32 {
    guard_ffi(|| {
        if out_enrollment_id.is_null() {
            return CB2000_TOD_ERR_INVALID_ARG;
        }
        // SAFETY: Caller guarantees `handle` is live until `cb2000_tod_close`.
        let h = match unsafe { borrow_handle(handle) } {
            Ok(h) => h,
            Err(code) => return code,
        };

        let _op_guard = h.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        h.clear_error();
        h.cancel.store(false, Ordering::SeqCst);
        let pctx = SendPtr(progress_ctx);

        let res: Result<IdentifyOutcome, ProtoError> = h.rt.block_on(async {
            emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_FINGER_NEEDED, 0);
            h.dev
                .wait_for_capture(
                    CapturePurpose::Identify,
                    h.cancel.clone(),
                    Some(CAPTURE_WAIT_TIMEOUT),
                    |ev| {
                        if ev == CaptureEvent::RetryNeeded {
                            emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_RETRY_SCAN, 0);
                        }
                    },
                )
                .await?;

            emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_FINGER_PRESENT, 0);
            let outcome = h.dev.identify_captured().await;
            emit_progress(progress_cb, pctx, CB2000_TOD_EVENT_FINGER_REMOVED, 0);
            outcome
        });

        match res {
            Ok(IdentifyOutcome::Match {
                sub_factor,
                enrollment_id,
                ..
            }) => {
                if !out_sub_factor.is_null() {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        *out_sub_factor = sub_factor;
                    }
                }
                // SAFETY: `out_enrollment_id` was verified non-null and writable for 32 bytes.
                let out_slice =
                    unsafe { slice::from_raw_parts_mut(out_enrollment_id, SDCP_DIGEST_LEN) };
                out_slice.copy_from_slice(&enrollment_id);
                CB2000_TOD_OK
            }
            Ok(IdentifyOutcome::NoMatch) => {
                h.set_error("no matching template found on sensor".to_string());
                CB2000_TOD_ERR_NO_MATCH
            }
            Ok(IdentifyOutcome::BadCapture { code }) => {
                if !out_bad_capture_code.is_null() {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        *out_bad_capture_code = code;
                    }
                }
                h.set_error(format!("bad capture quality (code=0x{code:02x})"));
                CB2000_TOD_ERR_BAD_CAPTURE
            }
            Err(e) => record_proto_error(h, e),
        }
    })
}

/// Enumerate occupied template slots owned by this Linux host partition.
///
/// # Safety
/// `handle` and `out_count` must be non-null; if `max_slots > 0`, `out_slots` must be writable
/// for at least `max_slots` elements.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_list_slots(
    handle: *const Cb2000TodHandle,
    out_slots: *mut Cb2000TodSlot,
    max_slots: usize,
    out_count: *mut usize,
) -> i32 {
    guard_ffi(|| {
        if out_count.is_null() || (max_slots > 0 && out_slots.is_null()) {
            return CB2000_TOD_ERR_INVALID_ARG;
        }
        // SAFETY: Caller guarantees `handle` is live until `cb2000_tod_close`.
        let h = match unsafe { borrow_handle(handle) } {
            Ok(h) => h,
            Err(code) => return code,
        };

        let _op_guard = h.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        h.clear_error();

        let owned = match h.rt.block_on(h.dev.list_owned_slots()) {
            Ok(slots) => slots,
            Err(e) => return record_proto_error(h, e),
        };

        let copy_len = owned.len().min(max_slots);
        if copy_len > 0 {
            // SAFETY: `out_slots` was checked non-null and writable for `max_slots >= copy_len`.
            let dst = unsafe { slice::from_raw_parts_mut(out_slots, copy_len) };
            for (d, s) in dst.iter_mut().zip(owned.iter().take(copy_len)) {
                *d = Cb2000TodSlot {
                    slot_index: s.slot_index,
                    sub_factor: s.sub_factor,
                    enrollment_id: s.enrollment_id,
                };
            }
        }
        // SAFETY: `out_count` was checked non-null above.
        unsafe {
            *out_count = copy_len;
        }
        CB2000_TOD_OK
    })
}

/// Delete the Linux-owned sensor slot(s) whose 32-byte `enrollment_id` matches in constant time.
///
/// # Safety
/// `handle` must be valid and `enrollment_id` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_delete_by_id(
    handle: *const Cb2000TodHandle,
    enrollment_id: *const u8,
) -> i32 {
    guard_ffi(|| {
        if enrollment_id.is_null() {
            return CB2000_TOD_ERR_INVALID_ARG;
        }
        // SAFETY: `enrollment_id` is non-null and readable for 32 bytes.
        let target: [u8; SDCP_DIGEST_LEN] = match unsafe {
            slice::from_raw_parts(enrollment_id, SDCP_DIGEST_LEN)
        }
        .try_into()
        {
            Ok(arr) => arr,
            Err(_) => return CB2000_TOD_ERR_INVALID_ARG,
        };

        // SAFETY: Caller guarantees `handle` is live until `cb2000_tod_close`.
        let h = match unsafe { borrow_handle(handle) } {
            Ok(h) => h,
            Err(code) => return code,
        };

        let _op_guard = h.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        h.clear_error();

        let deleted = match h.rt.block_on(async {
            let owned = h.dev.list_owned_slots().await?;
            let mut count = 0usize;
            for slot in owned {
                if bool::from(slot.enrollment_id.ct_eq(&target)) {
                    h.dev.delete_owned_slot(slot.slot_index).await?;
                    count += 1;
                }
            }
            Ok::<usize, ProtoError>(count)
        }) {
            Ok(n) => n,
            Err(e) => return record_proto_error(h, e),
        };

        if deleted == 0 {
            h.set_error("no matching enrollment_id on sensor".to_string());
            return CB2000_TOD_ERR_NOT_FOUND;
        }
        CB2000_TOD_OK
    })
}

/// Delete all template slots owned by this Linux host's partition (preserving other OS slots).
///
/// # Safety
/// `handle` must be valid; `out_deleted` may be null.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_clear_storage(
    handle: *const Cb2000TodHandle,
    out_deleted: *mut usize,
) -> i32 {
    guard_ffi(|| {
        // SAFETY: Caller guarantees `handle` is live until `cb2000_tod_close`.
        let h = match unsafe { borrow_handle(handle) } {
            Ok(h) => h,
            Err(code) => return code,
        };

        let _op_guard = h.op_lock.lock().unwrap_or_else(|e| e.into_inner());
        h.clear_error();

        let deleted = match h.rt.block_on(h.dev.delete_all_owned_slots()) {
            Ok(n) => n,
            Err(e) => return record_proto_error(h, e),
        };

        if !out_deleted.is_null() {
            // SAFETY: `out_deleted` was verified non-null above.
            unsafe {
                *out_deleted = deleted;
            }
        }
        CB2000_TOD_OK
    })
}

/// Constant-time comparison of two 32-byte enrollment IDs.
///
/// # Safety
/// `a` and `b` must be null or point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_ct_eq_id(a: *const u8, b: *const u8) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Both pointers are verified non-null and readable for 32 bytes.
        let sa = unsafe { slice::from_raw_parts(a, SDCP_DIGEST_LEN) };
        // SAFETY: Both pointers are verified non-null and readable for 32 bytes.
        let sb = unsafe { slice::from_raw_parts(b, SDCP_DIGEST_LEN) };
        bool::from(sa.ct_eq(sb))
    }))
    .unwrap_or(false)
}

/// Copy the last recorded error message as a NUL-terminated UTF-8 string into `buf`.
///
/// Returns the number of bytes written excluding the NUL terminator.
///
/// # Safety
/// `handle` and `buf` may be null; if `buf` is non-null and `buf_len > 0`, `buf` must be
/// writable for `buf_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn cb2000_tod_last_error(
    handle: *const Cb2000TodHandle,
    buf: *mut u8,
    buf_len: usize,
) -> usize {
    if handle.is_null() || buf.is_null() || buf_len == 0 {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `handle` is verified non-null and guaranteed live by caller.
        let h = unsafe { &*handle };
        let msg = h
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let bytes = msg.as_bytes();
        let copy_len = bytes.len().min(buf_len - 1);
        // SAFETY: `buf` is writable for `buf_len` bytes and `copy_len < buf_len`.
        let out = unsafe { slice::from_raw_parts_mut(buf, buf_len) };
        out[..copy_len].copy_from_slice(&bytes[..copy_len]);
        out[copy_len] = 0;
        copy_len
    }))
    .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use cb2000_proto::types::{
        CmdDirection, ACCEPT_SAMPLE_RESULT_LEN, CHECK_DUP_RESULT_LEN, IDENTIFY_RESULT_LEN,
        MAX_SLOTS, SDCP_CONNECT_RESP_LEN, SLOT_ENTRY_V2_LEN,
    };
    use cb2000_sdcp::{kbkdf_counter_hmac_sha256, sdcp_mac, SDCP_FW_BINDING_PREFIX};
    use p256::ecdh::EphemeralSecret;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::PublicKey;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;

    struct MockSlot {
        valid: bool,
        sub_factor: u8,
        id: [u8; 32],
        pid: u8,
        uuid: [u8; 16],
    }

    struct MockUsbState {
        model_sk: SigningKey,
        model_cert_der: Vec<u8>,
        pending_hdr: Option<[u8; 12]>,
        in_queue: VecDeque<Vec<u8>>,
        mac_key: [u8; 32],
        enroll_nonce: [u8; 32],
        identify_nonce: [u8; 32],
        slots: Vec<MockSlot>,
        poll_count: u8,
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

    impl MockUsbState {
        fn new() -> Self {
            let mut rng = rand_core::OsRng;
            let model_sk = SigningKey::random(&mut rng);
            let model_cert_der = test_cert(&model_sk);
            let mut slots: Vec<MockSlot> = (0..MAX_SLOTS)
                .map(|_| MockSlot {
                    valid: false,
                    sub_factor: 0,
                    id: [0u8; 32],
                    pid: 0,
                    uuid: [0u8; 16],
                })
                .collect();
            slots[0] = MockSlot {
                valid: true,
                sub_factor: 1,
                id: [0xEE; 32],
                pid: 0,
                uuid: [0x11; 16], // Windows dual-boot slot
            };
            Self {
                model_sk,
                model_cert_der,
                pending_hdr: None,
                in_queue: VecDeque::new(),
                mac_key: [0u8; 32],
                enroll_nonce: [0x44; 32],
                identify_nonce: [0u8; 32],
                slots,
                poll_count: 0,
            }
        }

        fn handle_command(&mut self, hdr: [u8; 12], payload: Option<&[u8]>) {
            let op = hdr[1];
            let ok_status = vec![0u8; 5];
            let nonzero_status = vec![0x01, 0xef, 0xff, 0xff, 0xff];

            match op {
                0x01 => {
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
                    h.update(SDCP_FW_BINDING_PREFIX);
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
                    self.mac_key.copy_from_slice(&app[..32]);

                    let claim_hash: [u8; 32] = Sha256::digest(&claim).into();
                    let mac = sdcp_mac(&self.mac_key, b"connect", &[&claim_hash]).unwrap();

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

                    self.in_queue.push_back(ok_status);
                    self.in_queue.push_back(resp);
                }
                0x02 => {
                    self.in_queue.push_back(ok_status);
                }
                0x05 => {
                    self.poll_count = 0;
                    self.in_queue.push_back(ok_status);
                }
                0x06 => {
                    self.poll_count += 1;
                    let code = if self.poll_count < 2 { 0x01 } else { 0x00 };
                    self.in_queue.push_back(vec![code, 0, 0, 0, 0]);
                    self.in_queue.push_back(ok_status);
                }
                0x08 => {
                    self.in_queue.push_back(vec![0u8; ACCEPT_SAMPLE_RESULT_LEN]);
                    self.in_queue.push_back(ok_status);
                }
                0x09 => {
                    self.in_queue.push_back(self.enroll_nonce.to_vec());
                    self.in_queue.push_back(ok_status);
                }
                0x0A => {
                    let data = payload.unwrap();
                    let m_a: [u8; 32] = data[0..32].try_into().unwrap();
                    let pid = data[32];
                    let uuid: [u8; 16] = data[33..49].try_into().unwrap();
                    let free = self.slots.iter_mut().find(|s| !s.valid).unwrap();
                    free.valid = true;
                    free.sub_factor = hdr[2];
                    free.id = m_a;
                    free.pid = pid;
                    free.uuid = uuid;
                    self.in_queue.push_back(ok_status);
                }
                0x0B => {
                    self.identify_nonce.copy_from_slice(payload.unwrap());
                    self.in_queue.push_back(ok_status);
                }
                0x0C => {
                    let pid = hdr[2];
                    let mut resp = vec![0u8; IDENTIFY_RESULT_LEN];
                    let trailer = if let Some(slot) =
                        self.slots.iter().find(|s| s.valid && s.pid == pid)
                    {
                        resp[0] = 0x00;
                        resp[1] = slot.sub_factor;
                        resp[2..34].copy_from_slice(&slot.id);
                        let mac = sdcp_mac(
                            &self.mac_key,
                            b"identify",
                            &[&self.identify_nonce, &slot.id],
                        )
                        .unwrap();
                        resp[34..66].copy_from_slice(&mac);
                        ok_status
                    } else {
                        resp[0] = 0x0b;
                        nonzero_status
                    };
                    self.in_queue.push_back(resp);
                    self.in_queue.push_back(trailer);
                }
                0x0D => {
                    // 3 enroll stages (resp[0] = 4), 10 slots
                    self.in_queue.push_back(vec![4, MAX_SLOTS as u8]);
                    self.in_queue.push_back(ok_status);
                }
                0x0E => {
                    let mut out = Vec::with_capacity(MAX_SLOTS * SLOT_ENTRY_V2_LEN);
                    for (i, s) in self.slots.iter().enumerate() {
                        out.push(u8::from(s.valid));
                        out.push(i as u8);
                        out.push(s.sub_factor);
                        out.extend_from_slice(&s.id);
                        out.push(s.pid);
                        out.extend_from_slice(&s.uuid);
                    }
                    self.in_queue.push_back(out);
                    self.in_queue.push_back(ok_status);
                }
                0x0F => {
                    let idx = usize::from(hdr[2]);
                    self.slots[idx].valid = false;
                    self.in_queue.push_back(ok_status);
                }
                0x10 => {
                    let mut resp = vec![0u8; CHECK_DUP_RESULT_LEN];
                    resp[0] = 0x0b;
                    self.in_queue.push_back(resp);
                    self.in_queue.push_back(nonzero_status);
                }
                0x15 | 0x07 => {
                    self.in_queue.push_back(ok_status);
                }
                _ => panic!("unexpected mock opcode 0x{op:02x}"),
            }
        }
    }

    unsafe extern "C" fn mock_control_in(
        _ctx: *mut c_void,
        _req: u8,
        value: u16,
        _index: u16,
        buf: *mut u8,
        len: usize,
    ) -> i32 {
        let out = unsafe { slice::from_raw_parts_mut(buf, len) };
        out.fill(0);
        if value == 0x000d && len >= 1 {
            out[0] = 0x01; // Protocol V2 enabled
        }
        len.min(8) as i32
    }

    unsafe extern "C" fn mock_bulk_out(ctx: *mut c_void, buf: *const u8, len: usize) -> i32 {
        let st = unsafe { &mut *(ctx as *mut MockUsbState) };
        let data = unsafe { slice::from_raw_parts(buf, len) };
        if let Some(hdr) = st.pending_hdr.take() {
            st.handle_command(hdr, Some(data));
        } else {
            let hdr: [u8; 12] = data.try_into().unwrap();
            if hdr[0] == CmdDirection::DataOut as u8 {
                st.pending_hdr = Some(hdr);
            } else {
                st.handle_command(hdr, None);
            }
        }
        0
    }

    unsafe extern "C" fn mock_bulk_in(ctx: *mut c_void, buf: *mut u8, len: usize) -> i32 {
        let st = unsafe { &mut *(ctx as *mut MockUsbState) };
        let pkt = st.in_queue.pop_front().unwrap();
        let copy = pkt.len().min(len);
        let out = unsafe { slice::from_raw_parts_mut(buf, len) };
        out[..copy].copy_from_slice(&pkt[..copy]);
        copy as i32
    }

    unsafe extern "C" fn record_progress(kind: u32, value: u32, ctx: *mut c_void) {
        let events = unsafe { &mut *(ctx as *mut Vec<(u32, u32)>) };
        events.push((kind, value));
    }

    #[test]
    fn ffi_roundtrip_open_enroll_list_identify_delete_and_clear() {
        let mut mock = MockUsbState::new();
        let vtable = Cb2000UsbVtable {
            control_in: Some(mock_control_in),
            bulk_out: Some(mock_bulk_out),
            bulk_in: Some(mock_bulk_in),
        };
        let mut handle: *mut Cb2000TodHandle = ptr::null_mut();
        let mut caps = Cb2000TodCaps {
            protocol_version: 0,
            partition_id: 0,
            supports_finger_up_poll: 0,
            _reserved: 0,
            enroll_stages: 0,
            max_slots: 0,
        };

        let rc = unsafe {
            cb2000_tod_open(
                &vtable,
                (&mut mock as *mut MockUsbState).cast(),
                &mut handle,
                &mut caps,
            )
        };
        assert_eq!(rc, CB2000_TOD_OK);
        assert!(!handle.is_null());
        assert_eq!(caps.protocol_version, 2);
        assert_eq!(caps.partition_id, 1);
        assert_eq!(caps.enroll_stages, 3);
        assert_eq!(caps.max_slots, 10);

        // Enroll right-index-finger (sub_factor=7) across 3 stages
        let mut events: Vec<(u32, u32)> = Vec::new();
        let mut enrolled_id = [0u8; 32];
        let rc = unsafe {
            cb2000_tod_enroll(
                handle,
                7,
                Some(record_progress),
                (&mut events as *mut Vec<(u32, u32)>).cast(),
                enrolled_id.as_mut_ptr(),
            )
        };
        assert_eq!(rc, CB2000_TOD_OK);
        assert!(events.contains(&(CB2000_TOD_EVENT_STAGE_PASSED, 1)));
        assert!(events.contains(&(CB2000_TOD_EVENT_STAGE_PASSED, 2)));
        assert!(events.contains(&(CB2000_TOD_EVENT_STAGE_PASSED, 3)));

        // List Linux-owned slots (must exclude Windows slot 0)
        let mut slots = [Cb2000TodSlot {
            slot_index: 0,
            sub_factor: 0,
            enrollment_id: [0u8; 32],
        }; 10];
        let mut count = 0usize;
        let rc = unsafe { cb2000_tod_list_slots(handle, slots.as_mut_ptr(), 10, &mut count) };
        assert_eq!(rc, CB2000_TOD_OK);
        assert_eq!(count, 1);
        assert_eq!(slots[0].slot_index, 1);
        assert_eq!(slots[0].sub_factor, 7);
        assert!(unsafe {
            cb2000_tod_ct_eq_id(slots[0].enrollment_id.as_ptr(), enrolled_id.as_ptr())
        });

        // Identify matches & verifies SDCP MAC
        let mut matched_sub = 0u8;
        let mut matched_id = [0u8; 32];
        let mut bad_code = 0u8;
        let rc = unsafe {
            cb2000_tod_identify(
                handle,
                None,
                ptr::null_mut(),
                &mut matched_sub,
                matched_id.as_mut_ptr(),
                &mut bad_code,
            )
        };
        assert_eq!(rc, CB2000_TOD_OK);
        assert_eq!(matched_sub, 7);
        assert!(unsafe { cb2000_tod_ct_eq_id(matched_id.as_ptr(), enrolled_id.as_ptr()) });

        // Deleting a non-existent ID returns NOT_FOUND
        let missing_id = [0x99u8; 32];
        let rc = unsafe { cb2000_tod_delete_by_id(handle, missing_id.as_ptr()) };
        assert_eq!(rc, CB2000_TOD_ERR_NOT_FOUND);

        // Deleting our enrolled ID succeeds and identify now returns NO_MATCH
        let rc = unsafe { cb2000_tod_delete_by_id(handle, enrolled_id.as_ptr()) };
        assert_eq!(rc, CB2000_TOD_OK);

        let rc = unsafe {
            cb2000_tod_identify(
                handle,
                None,
                ptr::null_mut(),
                &mut matched_sub,
                matched_id.as_mut_ptr(),
                &mut bad_code,
            )
        };
        assert_eq!(rc, CB2000_TOD_ERR_NO_MATCH);

        // Windows slot 0 remains untouched; clear_storage returns 0 after delete_by_id
        let mut deleted = 99usize;
        let rc = unsafe { cb2000_tod_clear_storage(handle, &mut deleted) };
        assert_eq!(rc, CB2000_TOD_OK);
        assert_eq!(deleted, 0);
        assert!(mock.slots[0].valid);

        unsafe {
            cb2000_tod_close(handle);
        }
    }
}
