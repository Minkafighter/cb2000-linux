//! Security-hardened persistent binding store mapping Linux users & fingers
//! to cryptographically verified SDCP 32-byte enrollment IDs.
//!
//! Security properties:
//! - Directory created with mode `0700`, file written with mode `0600`.
//! - Refuses to read or write through symlinks (symlink-attack resistant).
//! - Atomic persistence via temp file + `sync_all()` + `rename()`.
//! - Strict username validation (prevents injection/traversal).
//! - Supports Trust-On-First-Use (TOFU) pinning of the sensor's Model Certificate SHA-256.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub(crate) const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub(crate) const O_NOFOLLOW: i32 = 0o400_000;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid username")]
    InvalidUsername,

    #[error("refusing to operate on symlink path: {0}")]
    SymlinkRefused(PathBuf),

    #[error("insecure ownership or permissions on store path: {0}")]
    InsecurePermissions(PathBuf),

    #[error("corrupted TOFU pin in enrollment store: {0}")]
    CorruptedPin(&'static str),

    #[error("store I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("store JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// A single binding between a Linux user/finger and an on-chip SDCP enrollment ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub username: String,
    pub finger_name: String,
    pub sub_factor: u8,
    pub slot_index: Option<u8>,
    /// Lowercase hex-encoded 32-byte SDCP `enrollment_id`.
    pub enrollment_id_hex: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreData {
    version: u32,
    /// Optional TOFU-pinned SHA-256 hex digest of the hardware sensor's X.509 Model Certificate.
    pinned_model_cert_sha256: Option<String>,
    /// Optional TOFU-pinned SHA-256 hex digest of the sensor's per-device public key (`pk_d`).
    #[serde(default)]
    pinned_device_pubkey_sha256: Option<String>,
    records: Vec<EnrollmentRecord>,
}

/// Root-owned persistent store for user-to-template bindings.
pub struct EnrollmentStore {
    dir: PathBuf,
    file: PathBuf,
    data: StoreData,
}

impl EnrollmentStore {
    /// Load (or initialize) the store in `dir` (default: `/var/lib/cb2000-fprintd`).
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        let my_uid = current_uid()?;

        match fs::symlink_metadata(&dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(StoreError::SymlinkRefused(dir));
                }
                if !meta.is_dir() {
                    return Err(StoreError::InsecurePermissions(dir));
                }
                let mode = meta.permissions().mode() & 0o777;
                if meta.uid() != my_uid || (mode & 0o022) != 0 {
                    return Err(StoreError::InsecurePermissions(dir));
                }
                if (mode & 0o077) != 0 {
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&dir)?;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
            Err(e) => return Err(e.into()),
        }

        let file = dir.join("enrollments.json");
        let data: StoreData = match fs::symlink_metadata(&file) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(StoreError::SymlinkRefused(file));
                }
                if !meta.is_file() {
                    return Err(StoreError::InsecurePermissions(file));
                }
                let mode = meta.permissions().mode() & 0o777;
                if meta.uid() != my_uid || (mode & 0o077) != 0 {
                    return Err(StoreError::InsecurePermissions(file));
                }
                let mut f = OpenOptions::new()
                    .read(true)
                    .custom_flags(O_NOFOLLOW)
                    .open(&file)?;
                let mut raw = String::new();
                f.read_to_string(&mut raw)?;
                serde_json::from_str(&raw)?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => StoreData {
                version: 1,
                pinned_model_cert_sha256: None,
                pinned_device_pubkey_sha256: None,
                records: Vec::new(),
            },
            Err(e) => return Err(e.into()),
        };

        // Fail closed if persisted TOFU pins are malformed.
        if let Some(ref hex_str) = data.pinned_model_cert_sha256 {
            parse_hex_32(hex_str).ok_or(StoreError::CorruptedPin("pinned_model_cert_sha256"))?;
        }
        if let Some(ref hex_str) = data.pinned_device_pubkey_sha256 {
            parse_hex_32(hex_str)
                .ok_or(StoreError::CorruptedPin("pinned_device_pubkey_sha256"))?;
        }

        Ok(Self { dir, file, data })
    }

    /// Return the TOFU-pinned Model Certificate SHA-256 (if recorded).
    pub fn pinned_model_cert_sha256(&self) -> Option<[u8; 32]> {
        self.data
            .pinned_model_cert_sha256
            .as_deref()
            .and_then(parse_hex_32)
    }

    /// Return the TOFU-pinned per-device public key (`pk_d`) SHA-256 (if recorded).
    pub fn pinned_device_pubkey_sha256(&self) -> Option<[u8; 32]> {
        self.data
            .pinned_device_pubkey_sha256
            .as_deref()
            .and_then(parse_hex_32)
    }

    /// Persist both TOFU pins (Model Certificate SHA-256 and per-device `pk_d` SHA-256)
    /// transactionally (in-memory state only updates after durable disk write succeeds).
    pub fn set_tofu_pins(
        &mut self,
        model_cert_sha256: [u8; 32],
        device_pubkey_sha256: [u8; 32],
    ) -> Result<(), StoreError> {
        let mut next = self.data.clone();
        next.pinned_model_cert_sha256 = Some(hex::encode(model_cert_sha256));
        next.pinned_device_pubkey_sha256 = Some(hex::encode(device_pubkey_sha256));
        self.save_data(&next)?;
        self.data = next;
        Ok(())
    }

    /// List all enrolled finger names for `username`.
    pub fn list_fingers(&self, username: &str) -> Result<Vec<String>, StoreError> {
        validate_username(username)?;
        Ok(self
            .data
            .records
            .iter()
            .filter(|r| r.username == username)
            .map(|r| r.finger_name.clone())
            .collect())
    }

    /// Insert or replace an enrollment binding for `(username, finger_name)` transactionally,
    /// returning any previously bound record that was replaced.
    pub fn upsert(
        &mut self,
        record: EnrollmentRecord,
    ) -> Result<Option<EnrollmentRecord>, StoreError> {
        validate_username(&record.username)?;
        let mut next = self.data.clone();
        let replaced = next
            .records
            .iter()
            .position(|r| r.username == record.username && r.finger_name == record.finger_name)
            .map(|idx| next.records.remove(idx));
        next.records.push(record);
        self.save_data(&next)?;
        self.data = next;
        Ok(replaced)
    }

    /// Find an enrollment matching the given verified 32-byte `enrollment_id` AND belonging
    /// strictly to `expected_username` (and optionally `expected_finger`, unless `"any"`).
    ///
    /// Security invariant: Templates enrolled by user B can NEVER satisfy a verify for user A.
    pub fn find_authorized_match(
        &self,
        expected_username: &str,
        expected_finger: &str,
        verified_enrollment_id: &[u8; 32],
    ) -> Result<Option<&EnrollmentRecord>, StoreError> {
        validate_username(expected_username)?;
        let id_hex = hex::encode(verified_enrollment_id);
        Ok(self.data.records.iter().find(|r| {
            r.username == expected_username
                && (expected_finger == "any" || r.finger_name == expected_finger)
                && bool::from(r.enrollment_id_hex.as_bytes().ct_eq(id_hex.as_bytes()))
        }))
    }

    /// Remove and return all records belonging to `username` transactionally.
    pub fn remove_user(&mut self, username: &str) -> Result<Vec<EnrollmentRecord>, StoreError> {
        validate_username(username)?;
        let mut next = self.data.clone();
        let (removed, kept): (Vec<_>, Vec<_>) = next
            .records
            .drain(..)
            .partition(|r| r.username == username);
        next.records = kept;
        if !removed.is_empty() {
            self.save_data(&next)?;
            self.data = next;
        }
        Ok(removed)
    }

    /// Remove and return a single `(username, finger_name)` record if present, transactionally.
    pub fn remove_finger(
        &mut self,
        username: &str,
        finger_name: &str,
    ) -> Result<Option<EnrollmentRecord>, StoreError> {
        validate_username(username)?;
        let mut next = self.data.clone();
        let pos = next
            .records
            .iter()
            .position(|r| r.username == username && r.finger_name == finger_name);
        let removed = pos.map(|i| next.records.remove(i));
        if removed.is_some() {
            self.save_data(&next)?;
            self.data = next;
        }
        Ok(removed)
    }

    /// Prune any local records whose `enrollment_id` no longer exists on the sensor.
    pub fn retain_present_ids(&mut self, present_ids: &[[u8; 32]]) -> Result<usize, StoreError> {
        let hex_set: std::collections::HashSet<String> =
            present_ids.iter().map(hex::encode).collect();
        let mut next = self.data.clone();
        let before = next.records.len();
        next.records
            .retain(|r| hex_set.contains(&r.enrollment_id_hex));
        let removed = before - next.records.len();
        if removed > 0 {
            self.save_data(&next)?;
            self.data = next;
        }
        Ok(removed)
    }

    fn save_data(&self, data: &StoreData) -> Result<(), StoreError> {
        ensure_not_symlink(&self.dir)?;
        ensure_not_symlink(&self.file)?;

        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!(".enrollments.json.tmp.{}.{seq}", std::process::id()));
        ensure_not_symlink(&tmp)?;

        let payload = serde_json::to_vec_pretty(data)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&tmp)?;
        if let Err(e) = f.write_all(&payload).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        drop(f);

        if let Err(e) = fs::rename(&tmp, &self.file) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        if let Ok(dir_fd) = File::open(&self.dir) {
            let _ = dir_fd.sync_all();
        }
        Ok(())
    }
}

fn current_uid() -> Result<u32, StoreError> {
    Ok(fs::metadata("/proc/self")?.uid())
}

fn parse_hex_32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

/// Validate a POSIX username strictly to avoid injection or path anomalies.
pub fn validate_username(username: &str) -> Result<(), StoreError> {
    if username.is_empty() || username.len() > 64 {
        return Err(StoreError::InvalidUsername);
    }
    if username.starts_with('-') || username == "." || username == ".." {
        return Err(StoreError::InvalidUsername);
    }
    if !username
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(StoreError::InvalidUsername);
    }
    Ok(())
}

fn ensure_not_symlink(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(StoreError::SymlinkRefused(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_strict_user_isolation() {
        let tmp = std::env::temp_dir().join(format!("cb2000-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let mut store = EnrollmentStore::open(&tmp).unwrap();

        let alice_id = [0xAAu8; 32];
        let bob_id = [0xBBu8; 32];

        store
            .upsert(EnrollmentRecord {
                username: "alice".into(),
                finger_name: "right-index-finger".into(),
                sub_factor: 7,
                slot_index: Some(1),
                enrollment_id_hex: hex::encode(alice_id),
            })
            .unwrap();
        store
            .upsert(EnrollmentRecord {
                username: "bob".into(),
                finger_name: "right-index-finger".into(),
                sub_factor: 7,
                slot_index: Some(2),
                enrollment_id_hex: hex::encode(bob_id),
            })
            .unwrap();

        // Bob's fingerprint MUST NOT authenticate Alice!
        assert!(store
            .find_authorized_match("alice", "any", &bob_id)
            .unwrap()
            .is_none());
        // Alice's fingerprint authenticates Alice for "any" or "right-index-finger"
        assert!(store
            .find_authorized_match("alice", "any", &alice_id)
            .unwrap()
            .is_some());
        assert!(store
            .find_authorized_match("alice", "left-thumb", &alice_id)
            .unwrap()
            .is_none());

        // Reload from disk and verify persistence + permissions
        let reloaded = EnrollmentStore::open(&tmp).unwrap();
        assert_eq!(reloaded.list_fingers("alice").unwrap(), vec!["right-index-finger"]);
        let mode = fs::metadata(tmp.join("enrollments.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_invalid_usernames() {
        assert!(validate_username("").is_err());
        assert!(validate_username("../root").is_err());
        assert!(validate_username("-root").is_err());
        assert!(validate_username("alice\0bob").is_err());
        assert!(validate_username("alice").is_ok());
    }

    #[test]
    fn rejects_corrupted_tofu_pin_and_dangling_symlink() {
        let tmp = std::env::temp_dir().join(format!("cb2000-store-sec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).unwrap();

        // Legacy store without `pinned_device_pubkey_sha256` must load cleanly.
        let file = tmp.join("enrollments.json");
        let valid_pin = hex::encode([0x11u8; 32]);
        let legacy_json = format!(
            r#"{{"version":1,"pinned_model_cert_sha256":"{valid_pin}","records":[]}}"#
        );
        fs::write(&file, legacy_json).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let store = EnrollmentStore::open(&tmp).unwrap();
        assert_eq!(store.pinned_model_cert_sha256(), Some([0x11u8; 32]));
        assert_eq!(store.pinned_device_pubkey_sha256(), None);

        // Corrupted pin hex MUST fail closed.
        fs::write(
            &file,
            r#"{"version":1,"pinned_model_cert_sha256":"not-valid-hex","records":[]}"#,
        )
        .unwrap();
        assert!(matches!(
            EnrollmentStore::open(&tmp),
            Err(StoreError::CorruptedPin("pinned_model_cert_sha256"))
        ));

        // Dangling symlink at enrollments.json MUST be refused.
        fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(tmp.join("does-not-exist"), &file).unwrap();
        assert!(matches!(
            EnrollmentStore::open(&tmp),
            Err(StoreError::SymlinkRefused(_))
        ));

        let _ = fs::remove_dir_all(&tmp);
    }
}
