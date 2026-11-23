//! Polkit authorization checks and pure-Rust D-Bus caller UID/username resolution.

use std::collections::HashMap;
use std::fs;
use std::process::Command;

use zbus::fdo::DBusProxy;
use zbus::names::UniqueName;
use zbus::zvariant::Value;
use zbus::{Connection, Proxy};

use crate::store::validate_username;

pub const ACTION_VERIFY: &str = "net.reactivated.fprint.device.verify";
pub const ACTION_ENROLL: &str = "net.reactivated.fprint.device.enroll";
pub const ACTION_SET_USERNAME: &str = "net.reactivated.fprint.device.setusername";

/// Resolve the Unix UID of a D-Bus sender via `org.freedesktop.DBus.GetConnectionUnixUser`.
pub async fn caller_uid(conn: &Connection, sender: &UniqueName<'_>) -> zbus::fdo::Result<u32> {
    let dbus = DBusProxy::new(conn).await?;
    let bus_name = zbus::names::BusName::Unique(sender.to_owned());
    dbus.get_connection_unix_user(bus_name).await
}

/// Resolve a Unix UID to its login username by scanning `/etc/passwd` and falling back
/// to `getent passwd <uid>` for NSS backends (e.g., `systemd-homed`, SSSD, LDAP).
pub fn uid_to_username(uid: u32) -> Option<String> {
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        if let Some(name) = parse_passwd_uid(&passwd, uid) {
            return Some(name);
        }
    }

    let output = Command::new("getent")
        .args(["passwd", &uid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    parse_passwd_uid(&stdout, uid)
}

fn parse_passwd_uid(content: &str, uid: u32) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split(':');
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(_pw) = parts.next() else {
            continue;
        };
        let Some(uid_str) = parts.next() else {
            continue;
        };
        if uid_str.parse::<u32>().ok() == Some(uid) && validate_username(name).is_ok() {
            return Some(name.to_string());
        }
    }
    None
}

/// Resolve target username for `Claim`/`ListEnrolledFingers`/`DeleteEnrolledFingers`,
/// enforcing Polkit `net.reactivated.fprint.device.setusername` whenever a non-root caller
/// targets a username different from their own UID.
pub async fn resolve_and_authorize_username(
    conn: &Connection,
    sender: &UniqueName<'_>,
    requested_username: &str,
) -> zbus::fdo::Result<String> {
    let uid = caller_uid(conn, sender).await?;
    let caller_name = uid_to_username(uid).ok_or_else(|| {
        zbus::fdo::Error::AuthFailed(format!("could not resolve UID {uid} to username"))
    })?;

    if requested_username.is_empty() {
        return Ok(caller_name);
    }

    validate_username(requested_username).map_err(|_| {
        zbus::fdo::Error::InvalidArgs(format!("invalid username: {requested_username}"))
    })?;

    if uid != 0 && requested_username != caller_name {
        check_polkit(conn, sender, ACTION_SET_USERNAME, true).await?;
    }

    Ok(requested_username.to_string())
}

/// Query `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` for `action_id`.
///
/// Root (`uid == 0`, e.g., `pam_fprintd` running inside GDM/SDDM/sudo/login) is always authorized.
pub async fn check_polkit(
    conn: &Connection,
    sender: &UniqueName<'_>,
    action_id: &str,
    allow_user_interaction: bool,
) -> zbus::fdo::Result<()> {
    let uid = caller_uid(conn, sender).await?;
    if uid == 0 {
        return Ok(());
    }

    let proxy = Proxy::new(
        conn,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    .map_err(|e| zbus::fdo::Error::AuthFailed(format!("polkit unavailable: {e}")))?;

    let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
    subject_details.insert("name", Value::from(sender.as_str()));
    let subject: (&str, HashMap<&str, Value<'_>>) = ("system-bus-name", subject_details);
    let details: HashMap<&str, &str> = HashMap::new();
    let flags: u32 = if allow_user_interaction { 1 } else { 0 };
    let cancellation_id = "";

    let (is_authorized, _is_challenge, _out_details): (bool, bool, HashMap<String, String>) = proxy
        .call(
            "CheckAuthorization",
            &(subject, action_id, details, flags, cancellation_id),
        )
        .await
        .map_err(|e| zbus::fdo::Error::AuthFailed(format!("polkit check failed: {e}")))?;

    if is_authorized {
        Ok(())
    } else {
        Err(zbus::fdo::Error::AccessDenied(format!(
            "Not authorized for action {action_id}"
        )))
    }
}
