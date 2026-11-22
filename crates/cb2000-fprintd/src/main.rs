//! `cb2000-fprintd`: Security-hardened Rust `net.reactivated.Fprint` D-Bus daemon
//! for CanvasBio CB2000 (Samsung Galaxy Book5 360) on Linux (KDE / GNOME / PAM).

mod dbus;
mod fingers;
mod polkit;
mod rate_limit;
mod store;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use futures_lite::StreamExt;
use tracing::{error, info, warn};
use zbus::fdo::DBusProxy;
use zbus::Connection;

use crate::dbus::{register_interfaces, DaemonState, BUS_NAME};

#[derive(Parser)]
#[command(
    name = "cb2000-fprintd",
    about = "Memory-safe Rust net.reactivated.Fprint D-Bus daemon for CanvasBio CB2000"
)]
struct Args {
    /// Directory for root-owned enrollment binding store (0700).
    #[arg(long, default_value = "/var/lib/cb2000-fprintd")]
    state_dir: PathBuf,

    /// Optional directory containing DER-encoded trusted CA certificates (.der/.crt) for Model Cert verification.
    #[arg(long)]
    trusted_ca_dir: Option<PathBuf>,

    /// Disable Trust-On-First-Use (TOFU) pinning of the sensor's Model Certificate SHA-256.
    #[arg(long, default_value_t = false)]
    no_tofu_pin: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let trusted_cas = load_trusted_cas(args.trusted_ca_dir.as_deref())?;

    let state = Arc::new(
        DaemonState::new(args.state_dir, !args.no_tofu_pin, trusted_cas)
            .context("Failed to initialize cb2000-fprintd state store")?,
    );

    info!(
        state_dir = %state.state_dir().display(),
        tofu_pinning = !args.no_tofu_pin,
        "Starting cb2000-fprintd"
    );

    let conn = Connection::system()
        .await
        .context("Failed to connect to the D-Bus system bus")?;

    register_interfaces(&conn.object_server(), state.clone(), conn.clone())
        .await
        .context("Failed to register net.reactivated.Fprint interfaces")?;

    if let Err(e) = state.probe_on_startup().await {
        warn!(error = %e, "Initial CB2000 probe deferred until first client request");
    }

    conn.request_name(BUS_NAME)
        .await
        .context("Failed to claim D-Bus name net.reactivated.Fprint (is upstream fprintd running?)")?;

    info!(bus_name = BUS_NAME, "Serving net.reactivated.Fprint on system bus");

    // Monitor client disconnects so orphaned claims/captures are cancelled immediately.
    let monitor_state = state.clone();
    let monitor_conn = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = monitor_name_owner_changes(monitor_conn, monitor_state).await {
            error!(error = %e, "NameOwnerChanged monitor exited");
        }
    });

    // Wait cleanly for SIGINT or SIGTERM.
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT; shutting down cb2000-fprintd");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM; shutting down cb2000-fprintd");
        }
    }

    Ok(())
}

async fn monitor_name_owner_changes(conn: Connection, state: Arc<DaemonState>) -> Result<()> {
    let proxy = DBusProxy::new(&conn).await?;
    let mut stream = proxy.receive_name_owner_changed().await?;
    while let Some(signal) = stream.next().await {
        if let Ok(args) = signal.args() {
            if args.new_owner().is_none() {
                if let Some(old) = args.old_owner().as_ref() {
                    state.handle_bus_name_lost(old.as_str(), &conn).await;
                }
            }
        }
    }
    Ok(())
}

fn load_trusted_cas(dir: Option<&std::path::Path>) -> Result<Vec<Vec<u8>>> {
    let Some(dir) = dir else {
        return Ok(Vec::new());
    };
    if !dir.exists() {
        warn!(dir = %dir.display(), "Trusted CA directory does not exist; skipping");
        return Ok(Vec::new());
    }
    let mut certs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            certs.push(std::fs::read(&path)?);
        }
    }
    info!(count = certs.len(), dir = %dir.display(), "Loaded trusted issuing CA certificates");
    Ok(certs)
}
