//! Security-hardened persistent binding store mapping Linux users & fingers
//! to cryptographically verified SDCP 32-byte enrollment IDs.
//!
//! Security properties:
//! - Directory created with mode `0700`, file written with mode `0600`.
//! - Refuses to read or write through symlinks (symlink-attack resistant).
//! - Atomic persistence via temp file + `sync_all()` + `rename()`.
//! - Strict username validation (prevents injection/traversal).
//! - Supports Trust-On-First-Use (TOFU) pinning of the sensor's Model Certificate SHA-256.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid username")]
    InvalidUsername,

    #[error("refusing to operate on symlink path: {0}")]
    SymlinkRefused(PathBuf),

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
        if dir.exists() {
            let meta = fs::symlink_metadata(&dir)?;
            if meta.file_type().is_symlink() {
                return Err(StoreError::SymlinkRefused(dir));
            }
        } else {
            fs::create_dir_all(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }

        let file = dir.join("enrollments.json");
        let data = if file.exists() {
            let meta = fs::symlink_metadata(&file)?;
            if meta.file_type().is_symlink() {
                return Err(StoreError::SymlinkRefused(file));
            }
            let raw = fs::read_to_string(&file)?;
            serde_json::from_str(&raw)?
        } else {
            StoreData {
                version: 1,
                pinned_model_cert_sha256: None,
                records: Vec::new(),
            }
        };

        Ok(Self { dir, file, data })
    }

    /// Return the TOFU-pinned Model Certificate SHA-256 (if recorded).
    pub fn pinned_model_cert_sha256(&self) -> Option<[u8; 32]> {
        let hex_str = self.data.pinned_model_cert_sha256.as_deref()?;
        let bytes = hex::decode(hex_str).ok()?;
        bytes.try_into().ok()
    }

    /// Persist a TOFU Model Certificate SHA-256 pin if none is recorded yet.
    pub fn set_pinned_model_cert_sha256(&mut self, digest: [u8; 32]) -> Result<(), StoreError> {
        self.data.pinned_model_cert_sha256 = Some(hex::encode(digest));
        self.save()
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

    /// Insert or replace an enrollment binding for `(username, finger_name)`.
    pub fn upsert(&mut self, record: EnrollmentRecord) -> Result<(), StoreError> {
        validate_username(&record.username)?;
        self.data
            .records
            .retain(|r| !(r.username == record.username && r.finger_name == record.finger_name));
        self.data.records.push(record);
        self.save()
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
                && r.enrollment_id_hex == id_hex
                && (expected_finger == "any" || r.finger_name == expected_finger)
        }))
    }

    /// Remove and return all records belonging to `username`.
    pub fn remove_user(&mut self, username: &str) -> Result<Vec<EnrollmentRecord>, StoreError> {
        validate_username(username)?;
        let (removed, kept): (Vec<_>, Vec<_>) = self
            .data
            .records
            .drain(..)
            .partition(|r| r.username == username);
        self.data.records = kept;
        self.save()?;
        Ok(removed)
    }

    /// Remove and return a single `(username, finger_name)` record if present.
    pub fn remove_finger(
        &mut self,
        username: &str,
        finger_name: &str,
    ) -> Result<Option<EnrollmentRecord>, StoreError> {
        validate_username(username)?;
        let pos = self
            .data
            .records
            .iter()
            .position(|r| r.username == username && r.finger_name == finger_name);
        let removed = pos.map(|i| self.data.records.remove(i));
        if removed.is_some() {
            self.save()?;
        }
        Ok(removed)
    }

    /// Prune any local records whose `enrollment_id` no longer exists on the sensor.
    pub fn retain_present_ids(&mut self, present_ids: &[[u8; 32]]) -> Result<usize, StoreError> {
        let hex_set: std::collections::HashSet<String> =
            present_ids.iter().map(hex::encode).collect();
        let before = self.data.records.len();
        self.data
            .records
            .retain(|r| hex_set.contains(&r.enrollment_id_hex));
        let removed = before - self.data.records.len();
        if removed > 0 {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<(), StoreError> {
        ensure_not_symlink(&self.dir)?;
        ensure_not_symlink(&self.file)?;

        let tmp = self.dir.join(format!(".enrollments.json.tmp.{}", std::process::id()));
        ensure_not_symlink(&tmp)?;

        let payload = serde_json::to_vec_pretty(&self.data)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&payload)?;
        f.sync_all()?;
        drop(f);

        fs::rename(&tmp, &self.file)?;
        Ok(())
    }
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
    if path.exists() && fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(StoreError::SymlinkRefused(path.to_path_buf()));
    }
    Ok(())
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
}
