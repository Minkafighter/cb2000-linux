//! `net.reactivated.Fprint.Manager` and `net.reactivated.Fprint.Device` D-Bus service
//! compatible with KDE Plasma, GNOME, `fprintd-*`, and `pam_fprintd.so`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cb2000_proto::transport::NusbTransport;
use cb2000_proto::types::{
    CaptureEvent, CapturePurpose, IdentifyOutcome, ProtoError, DEFAULT_ENROLL_STAGES,
};
use cb2000_proto::{derive_linux_host_uuid, Cb2000Device};
use cb2000_sdcp::AttestationPolicy;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zbus::message::Header;
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, Connection, DBusError, ObjectServer, SignalContext};

use crate::fingers::finger_name_to_sub_factor;
use crate::polkit::{
    check_polkit, resolve_and_authorize_username, ACTION_ENROLL, ACTION_VERIFY,
};
use crate::rate_limit::VerifyRateLimiter;
use crate::store::{EnrollmentRecord, EnrollmentStore};

pub const BUS_NAME: &str = "net.reactivated.Fprint";
pub const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
pub const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

/// Standard `net.reactivated.Fprint.Error.*` D-Bus error hierarchy expected by
/// KDE, GNOME, `fprintd-*`, and `pam_fprintd.so`.
#[derive(Debug, DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
pub enum FprintError {
    #[zbus(error)]
    ZBus(zbus::Error),
    ClaimDevice(String),
    AlreadyInUse(String),
    Internal(String),
    PermissionDenied(String),
    NoEnrolledPrints(String),
    NoActionInProgress(String),
    InvalidFingername(String),
    NoSuchDevice(String),
}

impl From<zbus::fdo::Error> for FprintError {
    fn from(e: zbus::fdo::Error) -> Self {
        match e {
            zbus::fdo::Error::AccessDenied(m) | zbus::fdo::Error::AuthFailed(m) => {
                FprintError::PermissionDenied(m)
            }
            other => FprintError::Internal(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveOp {
    None,
    Verifying,
    Enrolling,
}

struct ClaimState {
    owner_bus_name: String,
    username: String,
    op: ActiveOp,
    cancel_flag: Option<Arc<AtomicBool>>,
    task: Option<JoinHandle<()>>,
}

/// Shared daemon state protected by async mutexes.
pub struct DaemonState {
    state_dir: PathBuf,
    tofu_pinning: bool,
    trusted_ca_der: Vec<Vec<u8>>,
    host_uuid: [u8; 16],
    device: Mutex<Option<Cb2000Device<NusbTransport>>>,
    store: Mutex<EnrollmentStore>,
    claim: Mutex<Option<ClaimState>>,
    rate_limiter: Mutex<VerifyRateLimiter>,
    finger_needed: AtomicBool,
    finger_present: AtomicBool,
    enroll_stages: AtomicU32,
}

impl DaemonState {
    pub fn new(
        state_dir: PathBuf,
        tofu_pinning: bool,
        trusted_ca_der: Vec<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let store = EnrollmentStore::open(&state_dir)?;
        let host_uuid = derive_linux_host_uuid();
        Ok(Self {
            state_dir,
            tofu_pinning,
            trusted_ca_der,
            host_uuid,
            device: Mutex::new(None),
            store: Mutex::new(store),
            claim: Mutex::new(None),
            rate_limiter: Mutex::new(VerifyRateLimiter::default()),
            finger_needed: AtomicBool::new(false),
            finger_present: AtomicBool::new(false),
            enroll_stages: AtomicU32::new(DEFAULT_ENROLL_STAGES),
        })
    }

    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    /// Probe the sensor on daemon startup so read-only properties like
    /// `num-enroll-stages` reflect hardware capabilities before the first Claim().
    pub async fn probe_on_startup(&self) -> Result<(), FprintError> {
        self.ensure_device_connected(None).await
    }

    /// Ensure an active, SDCP-authenticated USB session is open, re-connecting if needed
    /// (for example after system suspend/resume).
    async fn ensure_device_connected(&self, conn: Option<&Connection>) -> Result<(), FprintError> {
        let mut guard = self.device.lock().await;
        if let Some(dev) = guard.as_ref() {
            if dev.sdcp_reconnect().await.is_ok() {
                return Ok(());
            }
            warn!("SDCP reconnect failed (possible suspend/resume); re-establishing fresh SDCP session");
            *guard = None;
        }

        let mut policy = AttestationPolicy {
            pinned_model_cert_sha256: Vec::new(),
            trusted_issuer_certs_der: self.trusted_ca_der.clone(),
        };

        if self.tofu_pinning {
            let store = self.store.lock().await;
            if let Some(pin) = store.pinned_model_cert_sha256() {
                policy.pinned_model_cert_sha256.push(pin);
            }
        }

        let transport = NusbTransport::open_default()
            .map_err(|e| FprintError::Internal(format!("USB open failed: {e}")))?;
        let dev = Cb2000Device::open(transport, &policy, self.host_uuid)
            .await
            .map_err(|e| FprintError::Internal(format!("SDCP init failed: {e}")))?;
        let new_stages = dev.capabilities().enroll_stages;
        let prev_stages = self.enroll_stages.swap(new_stages, Ordering::SeqCst);

        // Record TOFU pin on first successful verified SDCP handshake.
        if self.tofu_pinning {
            let mut store = self.store.lock().await;
            if store.pinned_model_cert_sha256().is_none() {
                let sha = dev.attestation().model_cert_sha256;
                if let Err(e) = store.set_pinned_model_cert_sha256(sha) {
                    warn!(error = %e, "Failed to persist TOFU Model Cert SHA-256 pin");
                } else {
                    info!(cert_sha256 = %hex::encode(sha), "Recorded TOFU pin for sensor Model Certificate");
                }
            }
        }

        // Sync local binding store with templates actually present on our Linux partition.
        if let Ok(owned) = dev.list_owned_slots().await {
            let ids: Vec<[u8; 32]> = owned.iter().map(|s| s.enrollment_id).collect();
            let mut store = self.store.lock().await;
            if let Ok(pruned) = store.retain_present_ids(&ids) {
                if pruned > 0 {
                    info!(pruned, "Pruned stale local enrollment bindings not present on sensor");
                }
            }
        }

        *guard = Some(dev);
        drop(guard);

        if prev_stages != new_stages {
            if let Some(c) = conn {
                emit_num_enroll_stages_changed(c).await;
            }
        }
        Ok(())
    }

    /// Clean up if a D-Bus client that holds the active claim disconnects unexpectedly.
    pub async fn handle_bus_name_lost(&self, lost_name: &str, conn: &Connection) {
        let task_to_wait = {
            let mut claim_guard = self.claim.lock().await;
            let matches = claim_guard
                .as_ref()
                .is_some_and(|c| c.owner_bus_name == lost_name);
            if !matches {
                return;
            }
            warn!(owner = lost_name, "Claiming client disconnected; cancelling active operation and releasing claim");
            let mut state = match claim_guard.take() {
                Some(s) => s,
                None => return,
            };
            if let Some(flag) = state.cancel_flag.take() {
                flag.store(true, Ordering::SeqCst);
            }
            state.task.take()
        };

        set_finger_needed(self, conn, false).await;
        set_finger_present(self, conn, false).await;
        if let Some(handle) = task_to_wait {
            let _ = handle.await;
        }
    }
}

/// D-Bus object at `/net/reactivated/Fprint/Manager`.
pub struct FprintManager {
    device_path: OwnedObjectPath,
}

impl FprintManager {
    pub fn new() -> Result<Self, zbus::zvariant::Error> {
        Ok(Self {
            device_path: OwnedObjectPath::try_from(DEVICE_PATH)?,
        })
    }
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl FprintManager {
    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        vec![self.device_path.clone()]
    }

    async fn get_default_device(&self) -> Result<OwnedObjectPath, FprintError> {
        Ok(self.device_path.clone())
    }
}

/// D-Bus object at `/net/reactivated/Fprint/Device/0`.
pub struct FprintDevice {
    state: Arc<DaemonState>,
    conn: Connection,
}

impl FprintDevice {
    pub fn new(state: Arc<DaemonState>, conn: Connection) -> Self {
        Self { state, conn }
    }

    async fn assert_claimer(&self, sender: &str) -> Result<String, FprintError> {
        let guard = self.state.claim.lock().await;
        match guard.as_ref() {
            Some(c) if c.owner_bus_name == sender => Ok(c.username.clone()),
            Some(_) => Err(FprintError::AlreadyInUse(
                "Device is claimed by another client".into(),
            )),
            None => Err(FprintError::ClaimDevice(
                "Client must call Claim() before using the device".into(),
            )),
        }
    }

    async fn stop_active_op_internal(
        &self,
        sender: &str,
        expected: Option<ActiveOp>,
    ) -> Result<(), FprintError> {
        let handle = {
            let mut guard = self.state.claim.lock().await;
            let claim = match guard.as_mut() {
                Some(c) if c.owner_bus_name == sender => c,
                Some(_) => {
                    return Err(FprintError::AlreadyInUse(
                        "Device is claimed by another client".into(),
                    ))
                }
                None => return Err(FprintError::ClaimDevice("Device not claimed".into())),
            };
            if let Some(exp) = expected {
                if claim.op != exp {
                    return Err(FprintError::NoActionInProgress(
                        "No matching operation is currently running".into(),
                    ));
                }
            }
            if let Some(flag) = claim.cancel_flag.take() {
                flag.store(true, Ordering::SeqCst);
            }
            claim.op = ActiveOp::None;
            claim.task.take()
        };

        set_finger_needed(&self.state, &self.conn, false).await;
        set_finger_present(&self.state, &self.conn, false).await;
        if let Some(h) = handle {
            let _ = h.await;
        }
        Ok(())
    }

    async fn delete_records_on_chip_and_store(
        &self,
        records: Vec<EnrollmentRecord>,
    ) -> Result<(), FprintError> {
        if records.is_empty() {
            return Ok(());
        }
        self.state.ensure_device_connected(Some(&self.conn)).await?;
        let guard = self.state.device.lock().await;
        let Some(dev) = guard.as_ref() else {
            return Err(FprintError::Internal("device disconnected".into()));
        };
        let owned = dev
            .list_owned_slots()
            .await
            .map_err(|e| FprintError::Internal(format!("enumerate slots failed: {e}")))?;

        for rec in &records {
            for slot in &owned {
                if hex::encode(slot.enrollment_id) == rec.enrollment_id_hex {
                    if let Err(e) = dev.delete_owned_slot(slot.slot_index).await {
                        warn!(slot = slot.slot_index, error = %e, "Failed to delete slot from chip");
                    }
                }
            }
        }
        Ok(())
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl FprintDevice {
    #[zbus(property, name = "name")]
    async fn name(&self) -> String {
        "CanvasBio CB2000 Match-on-Chip".to_string()
    }

    #[zbus(property, name = "num-enroll-stages")]
    async fn num_enroll_stages(&self) -> i32 {
        self.state.enroll_stages.load(Ordering::SeqCst) as i32
    }

    #[zbus(property, name = "scan-type")]
    async fn scan_type(&self) -> String {
        "press".to_string()
    }

    #[zbus(property, name = "finger-present")]
    async fn finger_present(&self) -> bool {
        self.state.finger_present.load(Ordering::SeqCst)
    }

    #[zbus(property, name = "finger-needed")]
    async fn finger_needed(&self) -> bool {
        self.state.finger_needed.load(Ordering::SeqCst)
    }

    async fn list_enrolled_fingers(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        username: &str,
    ) -> Result<Vec<String>, FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        check_polkit(&self.conn, sender, ACTION_VERIFY, false).await?;
        let target_user = resolve_and_authorize_username(&self.conn, sender, username).await?;

        // Sync with hardware if attached; ignore transient open errors when simply listing.
        let _ = self.state.ensure_device_connected(Some(&self.conn)).await;

        let store = self.state.store.lock().await;
        let fingers = store
            .list_fingers(&target_user)
            .map_err(|e| FprintError::Internal(e.to_string()))?;
        if fingers.is_empty() {
            return Err(FprintError::NoEnrolledPrints(format!(
                "User {target_user} has no enrolled prints"
            )));
        }
        Ok(fingers)
    }

    async fn delete_enrolled_fingers(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        username: &str,
    ) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        check_polkit(&self.conn, sender, ACTION_ENROLL, true).await?;
        let target_user = resolve_and_authorize_username(&self.conn, sender, username).await?;

        let removed = {
            let mut store = self.state.store.lock().await;
            store
                .remove_user(&target_user)
                .map_err(|e| FprintError::Internal(e.to_string()))?
        };
        self.delete_records_on_chip_and_store(removed).await
    }

    async fn delete_enrolled_fingers2(
        &self,
        #[zbus(header)] hdr: Header<'_>,
    ) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        check_polkit(&self.conn, sender, ACTION_ENROLL, true).await?;
        let username = self.assert_claimer(sender.as_str()).await?;

        let removed = {
            let mut store = self.state.store.lock().await;
            store
                .remove_user(&username)
                .map_err(|e| FprintError::Internal(e.to_string()))?
        };
        self.delete_records_on_chip_and_store(removed).await
    }

    async fn delete_enrolled_finger(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        check_polkit(&self.conn, sender, ACTION_ENROLL, true).await?;
        let username = self.assert_claimer(sender.as_str()).await?;

        if finger_name_to_sub_factor(finger_name).is_none() {
            return Err(FprintError::InvalidFingername(format!(
                "Invalid finger name: {finger_name}"
            )));
        }

        let removed = {
            let mut store = self.state.store.lock().await;
            store
                .remove_finger(&username, finger_name)
                .map_err(|e| FprintError::Internal(e.to_string()))?
        };
        match removed {
            Some(rec) => self.delete_records_on_chip_and_store(vec![rec]).await,
            None => Err(FprintError::NoEnrolledPrints(format!(
                "Finger {finger_name} is not enrolled for user {username}"
            ))),
        }
    }

    async fn claim(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        username: &str,
    ) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        let target_user = resolve_and_authorize_username(&self.conn, sender, username).await?;

        {
            let guard = self.state.claim.lock().await;
            if let Some(existing) = guard.as_ref() {
                if existing.owner_bus_name != sender.as_str() {
                    return Err(FprintError::AlreadyInUse(
                        "Device is already claimed by another process".into(),
                    ));
                }
                return Ok(());
            }
        }

        // Establish / validate SDCP session before confirming the claim.
        self.state.ensure_device_connected(Some(&self.conn)).await?;

        let mut guard = self.state.claim.lock().await;
        if guard.is_some() {
            return Err(FprintError::AlreadyInUse("Device already claimed".into()));
        }
        *guard = Some(ClaimState {
            owner_bus_name: sender.to_string(),
            username: target_user.clone(),
            op: ActiveOp::None,
            cancel_flag: None,
            task: None,
        });
        info!(owner = %sender, user = %target_user, "Device claimed");
        Ok(())
    }

    async fn release(&self, #[zbus(header)] hdr: Header<'_>) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        self.stop_active_op_internal(sender.as_str(), None).await?;

        let mut guard = self.state.claim.lock().await;
        if guard
            .as_ref()
            .is_some_and(|c| c.owner_bus_name == sender.as_str())
        {
            *guard = None;
            info!(owner = %sender, "Device released");
            Ok(())
        } else {
            Err(FprintError::ClaimDevice(
                "Caller does not hold device claim".into(),
            ))
        }
    }

    async fn verify_start(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        check_polkit(&self.conn, sender, ACTION_VERIFY, false).await?;
        let username = self.assert_claimer(sender.as_str()).await?;

        if finger_name != "any" && finger_name_to_sub_factor(finger_name).is_none() {
            return Err(FprintError::InvalidFingername(format!(
                "Invalid finger name: {finger_name}"
            )));
        }

        // Enforce rate-limit lockout before touching hardware.
        {
            let rl = self.state.rate_limiter.lock().await;
            if let Err(remaining) = rl.check_allowed(&username) {
                warn!(
                    user = %username,
                    remaining_secs = remaining.as_secs(),
                    "Verification rejected due to consecutive failure rate-limit lockout"
                );
                return Err(FprintError::PermissionDenied(format!(
                    "Too many failed fingerprint attempts; try again in {}s",
                    remaining.as_secs().max(1)
                )));
            }
        }

        // Ensure target user actually has enrolled prints bound in our local root-owned store.
        let enrolled_fingers = {
            let store = self.state.store.lock().await;
            store
                .list_fingers(&username)
                .map_err(|e| FprintError::Internal(e.to_string()))?
        };
        if enrolled_fingers.is_empty()
            || (finger_name != "any" && !enrolled_fingers.iter().any(|f| f == finger_name))
        {
            return Err(FprintError::NoEnrolledPrints(format!(
                "No enrolled prints for user {username} ({finger_name})"
            )));
        }

        self.state.ensure_device_connected(Some(&self.conn)).await?;

        let cancel = Arc::new(AtomicBool::new(false));
        let target_finger = finger_name.to_string();
        let state = self.state.clone();
        let conn = self.conn.clone();

        {
            let mut guard = self.state.claim.lock().await;
            let Some(claim) = guard.as_mut() else {
                return Err(FprintError::ClaimDevice("Device not claimed".into()));
            };
            if claim.op != ActiveOp::None {
                return Err(FprintError::AlreadyInUse(
                    "Another operation is already in progress".into(),
                ));
            }
            claim.op = ActiveOp::Verifying;
            claim.cancel_flag = Some(cancel.clone());
        }

        set_finger_needed(&self.state, &self.conn, true).await;

        let task = tokio::spawn(async move {
            run_verify_task(state, conn, username, target_finger, cancel).await;
        });

        let mut guard = self.state.claim.lock().await;
        if let Some(claim) = guard.as_mut() {
            claim.task = Some(task);
        }
        Ok(())
    }

    async fn verify_stop(&self, #[zbus(header)] hdr: Header<'_>) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        self.stop_active_op_internal(sender.as_str(), Some(ActiveOp::Verifying))
            .await
    }

    async fn enroll_start(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        finger_name: &str,
    ) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        check_polkit(&self.conn, sender, ACTION_ENROLL, true).await?;
        let username = self.assert_claimer(sender.as_str()).await?;

        let sub_factor = finger_name_to_sub_factor(finger_name).ok_or_else(|| {
            FprintError::InvalidFingername(format!("Invalid finger name: {finger_name}"))
        })?;

        self.state.ensure_device_connected(Some(&self.conn)).await?;

        let cancel = Arc::new(AtomicBool::new(false));
        let finger_owned = finger_name.to_string();
        let state = self.state.clone();
        let conn = self.conn.clone();

        {
            let mut guard = self.state.claim.lock().await;
            let Some(claim) = guard.as_mut() else {
                return Err(FprintError::ClaimDevice("Device not claimed".into()));
            };
            if claim.op != ActiveOp::None {
                return Err(FprintError::AlreadyInUse(
                    "Another operation is already in progress".into(),
                ));
            }
            claim.op = ActiveOp::Enrolling;
            claim.cancel_flag = Some(cancel.clone());
        }

        set_finger_needed(&self.state, &self.conn, true).await;

        let task = tokio::spawn(async move {
            run_enroll_task(state, conn, username, finger_owned, sub_factor, cancel).await;
        });

        let mut guard = self.state.claim.lock().await;
        if let Some(claim) = guard.as_mut() {
            claim.task = Some(task);
        }
        Ok(())
    }

    async fn enroll_stop(&self, #[zbus(header)] hdr: Header<'_>) -> Result<(), FprintError> {
        let sender = hdr
            .sender()
            .ok_or_else(|| FprintError::PermissionDenied("missing D-Bus sender".into()))?;
        self.stop_active_op_internal(sender.as_str(), Some(ActiveOp::Enrolling))
            .await
    }

    #[zbus(signal)]
    async fn verify_finger_selected(
        ctxt: &SignalContext<'_>,
        finger_name: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(
        ctxt: &SignalContext<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn enroll_status(
        ctxt: &SignalContext<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;
}

async fn emit_verify_finger_selected(conn: &Connection, finger_name: &str) {
    if let Ok(iface) = conn
        .object_server()
        .interface::<_, FprintDevice>(DEVICE_PATH)
        .await
    {
        let _ = FprintDevice::verify_finger_selected(iface.signal_context(), finger_name).await;
    }
}

async fn emit_verify_status(conn: &Connection, result: &str, done: bool) {
    if let Ok(iface) = conn
        .object_server()
        .interface::<_, FprintDevice>(DEVICE_PATH)
        .await
    {
        let _ = FprintDevice::verify_status(iface.signal_context(), result, done).await;
    }
}

async fn emit_enroll_status(conn: &Connection, result: &str, done: bool) {
    if let Ok(iface) = conn
        .object_server()
        .interface::<_, FprintDevice>(DEVICE_PATH)
        .await
    {
        let _ = FprintDevice::enroll_status(iface.signal_context(), result, done).await;
    }
}

async fn emit_num_enroll_stages_changed(conn: &Connection) {
    if let Ok(iface) = conn
        .object_server()
        .interface::<_, FprintDevice>(DEVICE_PATH)
        .await
    {
        let _ = iface
            .get()
            .await
            .num_enroll_stages_changed(iface.signal_context())
            .await;
    }
}

async fn set_finger_needed(state: &DaemonState, conn: &Connection, needed: bool) {
    if state.finger_needed.swap(needed, Ordering::SeqCst) != needed {
        if let Ok(iface) = conn
            .object_server()
            .interface::<_, FprintDevice>(DEVICE_PATH)
            .await
        {
            let _ = iface
                .get()
                .await
                .finger_needed_changed(iface.signal_context())
                .await;
        }
    }
}

async fn set_finger_present(state: &DaemonState, conn: &Connection, present: bool) {
    if state.finger_present.swap(present, Ordering::SeqCst) != present {
        if let Ok(iface) = conn
            .object_server()
            .interface::<_, FprintDevice>(DEVICE_PATH)
            .await
        {
            let _ = iface
                .get()
                .await
                .finger_present_changed(iface.signal_context())
                .await;
        }
    }
}

async fn run_verify_task(
    state: Arc<DaemonState>,
    conn: Connection,
    username: String,
    target_finger: String,
    cancel: Arc<AtomicBool>,
) {
    // Allow zbus to flush the VerifyStart D-Bus reply before emitting VerifyFingerSelected;
    // pam_fprintd ignores signals received before VerifyStart returns.
    tokio::time::sleep(Duration::from_millis(10)).await;
    if cancel.load(Ordering::SeqCst) {
        set_finger_needed(&state, &conn, false).await;
        set_finger_present(&state, &conn, false).await;
        return;
    }
    emit_verify_finger_selected(&conn, &target_finger).await;

    let outcome = async {
        loop {
            let capture_res = {
                let guard = state.device.lock().await;
                let Some(dev) = guard.as_ref() else {
                    return ("verify-disconnected", true);
                };
                dev.wait_for_capture(
                    CapturePurpose::Identify,
                    cancel.clone(),
                    Some(Duration::from_secs(60)),
                    |ev| {
                        if ev == CaptureEvent::RetryNeeded {
                            let c = conn.clone();
                            tokio::spawn(async move {
                                emit_verify_status(&c, "verify-retry-scan", false).await;
                            });
                        }
                    },
                )
                .await
            };

            match capture_res {
                Ok(()) => {}
                Err(ProtoError::Cancelled) => return ("verify-no-match", true),
                Err(ProtoError::CaptureTimeout) => return ("verify-no-match", true),
                Err(e) => {
                    error!(error = %e, "Hardware error during verify capture");
                    return ("verify-disconnected", true);
                }
            }

            set_finger_present(&state, &conn, true).await;
            let id_res = {
                let guard = state.device.lock().await;
                let Some(dev) = guard.as_ref() else {
                    return ("verify-disconnected", true);
                };
                dev.identify_captured().await
            };
            set_finger_present(&state, &conn, false).await;

            match id_res {
                Ok(IdentifyOutcome::Match { enrollment_id, .. }) => {
                    // CRITICAL SECURITY CHECK:
                    // Even though hardware + SDCP MAC verified, we MUST confirm that
                    // `enrollment_id` is explicitly bound to `username` (and `target_finger`)
                    // in our root-owned persistent store!
                    let authorized = {
                        let store = state.store.lock().await;
                        store
                            .find_authorized_match(&username, &target_finger, &enrollment_id)
                            .ok()
                            .flatten()
                            .is_some()
                    };

                    if authorized {
                        state.rate_limiter.lock().await.record_success(&username);
                        info!(user = %username, "Fingerprint verified via SDCP + user binding");
                        return ("verify-match", true);
                    } else {
                        warn!(
                            user = %username,
                            "Hardware matched a template NOT bound to target user; rejecting!"
                        );
                        state.rate_limiter.lock().await.record_failure(&username);
                        return ("verify-no-match", true);
                    }
                }
                Ok(IdentifyOutcome::NoMatch) => {
                    state.rate_limiter.lock().await.record_failure(&username);
                    return ("verify-no-match", true);
                }
                Ok(IdentifyOutcome::BadCapture { .. }) => {
                    emit_verify_status(&conn, "verify-retry-scan", false).await;
                }
                Err(ProtoError::Sdcp(e)) => {
                    error!(error = %e, "SDCP cryptographic verification FAILED during verify!");
                    state.rate_limiter.lock().await.record_failure(&username);
                    return ("verify-unknown-error", true);
                }
                Err(e) => {
                    error!(error = %e, "Identify command failed");
                    return ("verify-disconnected", true);
                }
            }
        }
    }
    .await;

    set_finger_needed(&state, &conn, false).await;
    set_finger_present(&state, &conn, false).await;
    if !cancel.load(Ordering::SeqCst) {
        emit_verify_status(&conn, outcome.0, outcome.1).await;
    }
    let mut guard = state.claim.lock().await;
    if let Some(claim) = guard.as_mut() {
        if claim.op == ActiveOp::Verifying {
            claim.cancel_flag = None;
        }
    }
}

async fn run_enroll_task(
    state: Arc<DaemonState>,
    conn: Connection,
    username: String,
    finger_name: String,
    sub_factor: u8,
    cancel: Arc<AtomicBool>,
) {
    let final_status = async {
        // Check available capacity on chip before starting.
        {
            let guard = state.device.lock().await;
            let Some(dev) = guard.as_ref() else {
                return "enroll-disconnected";
            };
            match dev.enumerate_slots().await {
                Ok(slots) => {
                    let occupied = slots.iter().filter(|s| s.valid).count();
                    if occupied >= dev.capabilities().max_slots {
                        return "enroll-data-full";
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to check slot capacity");
                    return "enroll-disconnected";
                }
            }
        }

        let enroll_nonce = {
            let guard = state.device.lock().await;
            let Some(dev) = guard.as_ref() else {
                return "enroll-disconnected";
            };
            match dev.enroll_begin().await {
                Ok(n) => n,
                Err(ProtoError::SlotsFull(_)) => return "enroll-data-full",
                Err(e) => {
                    error!(error = %e, "EnrollBegin failed");
                    return "enroll-failed";
                }
            }
        };

        let total_stages = state.enroll_stages.load(Ordering::SeqCst);
        let mut stages_done = 0u32;
        while stages_done < total_stages {
            let cap_res = {
                let guard = state.device.lock().await;
                let Some(dev) = guard.as_ref() else {
                    return "enroll-disconnected";
                };
                dev.wait_for_capture(
                    CapturePurpose::Enroll,
                    cancel.clone(),
                    Some(Duration::from_secs(60)),
                    |ev| {
                        if ev == CaptureEvent::RetryNeeded {
                            let c = conn.clone();
                            tokio::spawn(async move {
                                emit_enroll_status(&c, "enroll-retry-scan", false).await;
                            });
                        }
                    },
                )
                .await
            };

            match cap_res {
                Ok(()) => {}
                Err(ProtoError::Cancelled) => return "enroll-failed",
                Err(ProtoError::CaptureTimeout) => return "enroll-failed",
                Err(e) => {
                    error!(error = %e, "Capture failed during enroll");
                    return "enroll-disconnected";
                }
            }

            set_finger_present(&state, &conn, true).await;
            let sample_res = {
                let guard = state.device.lock().await;
                let Some(dev) = guard.as_ref() else {
                    set_finger_present(&state, &conn, false).await;
                    return "enroll-disconnected";
                };
                dev.enroll_accept_sample().await
            };

            let need_finger_up = match sample_res {
                Ok(s) if s.accepted => {
                    stages_done += 1;
                    if stages_done < total_stages {
                        emit_enroll_status(&conn, "enroll-stage-passed", false).await;
                        true
                    } else {
                        false
                    }
                }
                Ok(_) => {
                    emit_enroll_status(&conn, "enroll-retry-scan", false).await;
                    true
                }
                Err(e) => {
                    set_finger_present(&state, &conn, false).await;
                    error!(error = %e, "AcceptEnrollSample failed");
                    return "enroll-failed";
                }
            };

            if need_finger_up {
                let lift_res = {
                    let guard = state.device.lock().await;
                    let Some(dev) = guard.as_ref() else {
                        set_finger_present(&state, &conn, false).await;
                        return "enroll-disconnected";
                    };
                    dev.wait_for_finger_up(
                        CapturePurpose::Enroll,
                        cancel.clone(),
                        Some(Duration::from_secs(30)),
                    )
                    .await
                };
                set_finger_present(&state, &conn, false).await;
                match lift_res {
                    Ok(()) => {}
                    Err(ProtoError::Cancelled | ProtoError::CaptureTimeout) => {
                        return "enroll-failed";
                    }
                    Err(e) => {
                        error!(error = %e, "Waiting for finger lift failed during enroll");
                        return "enroll-disconnected";
                    }
                }
            } else {
                set_finger_present(&state, &conn, false).await;
            }
        }

        // Check for duplicate before committing.
        {
            let guard = state.device.lock().await;
            let Some(dev) = guard.as_ref() else {
                return "enroll-disconnected";
            };
            if let Ok(Some(_)) = dev.check_duplicate().await {
                return "enroll-duplicate";
            }
        }

        // Commit enrollment with SDCP Enroll Authorization MAC.
        let enrollment_id = {
            let guard = state.device.lock().await;
            let Some(dev) = guard.as_ref() else {
                return "enroll-disconnected";
            };
            match dev.enroll_commit(sub_factor, &enroll_nonce).await {
                Ok(id) => id,
                Err(e) => {
                    error!(error = %e, "EnrollCommit failed");
                    return "enroll-failed";
                }
            }
        };

        // Determine assigned slot index and bind strictly to (username, finger_name).
        let slot_index = {
            let guard = state.device.lock().await;
            if let Some(dev) = guard.as_ref() {
                dev.list_owned_slots()
                    .await
                    .ok()
                    .and_then(|slots| {
                        slots
                            .into_iter()
                            .find(|s| s.enrollment_id == enrollment_id)
                            .map(|s| s.slot_index)
                    })
            } else {
                None
            }
        };

        let record = EnrollmentRecord {
            username: username.clone(),
            finger_name: finger_name.clone(),
            sub_factor,
            slot_index,
            enrollment_id_hex: hex::encode(enrollment_id),
        };
        if let Err(e) = state.store.lock().await.upsert(record) {
            error!(error = %e, "Failed to persist enrollment binding");
            return "enroll-unknown-error";
        }

        info!(user = %username, finger = %finger_name, "Enrollment completed and bound");
        "enroll-completed"
    }
    .await;

    set_finger_needed(&state, &conn, false).await;
    set_finger_present(&state, &conn, false).await;
    if !cancel.load(Ordering::SeqCst) {
        emit_enroll_status(&conn, final_status, true).await;
    }

    let mut guard = state.claim.lock().await;
    if let Some(claim) = guard.as_mut() {
        if claim.op == ActiveOp::Enrolling {
            claim.cancel_flag = None;
        }
    }
}

/// Register Manager and Device objects on the D-Bus `ObjectServer`.
pub async fn register_interfaces(
    server: &ObjectServer,
    state: Arc<DaemonState>,
    conn: Connection,
) -> anyhow::Result<()> {
    let manager = FprintManager::new()?;
    let device = FprintDevice::new(state, conn);
    server.at(MANAGER_PATH, manager).await?;
    server.at(DEVICE_PATH, device).await?;
    Ok(())
}
