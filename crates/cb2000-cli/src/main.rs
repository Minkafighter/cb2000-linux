//! Standalone diagnostic & management CLI for the CB2000 Match-on-Chip fingerprint sensor.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use cb2000_proto::transport::NusbTransport;
use cb2000_proto::types::{CaptureEvent, CapturePurpose, IdentifyOutcome};
use cb2000_proto::{derive_linux_host_uuid, Cb2000Device};
use cb2000_sdcp::AttestationPolicy;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cb2000-cli",
    about = "Clean-room Rust diagnostic CLI for CanvasBio CB2000 (2df0:0007)"
)]
struct Cli {
    /// Optional hex-encoded SHA-256 fingerprint of the expected X.509 Model Certificate.
    #[arg(long)]
    pin_cert_sha256: Option<String>,

    /// Optional path to a DER-encoded trusted issuing CA certificate for Model Cert verification.
    #[arg(long)]
    trusted_ca_der: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Probe USB capabilities, perform SDCP handshake + attestation, and test SDCP reconnect.
    Probe,
    /// List template slots on the sensor (marking which belong to this Linux partition).
    Slots,
    /// Interactively enroll a finger directly on the chip (for hardware testing).
    Enroll {
        /// Finger sub-factor ID (1..=10, e.g., 7 = right-index-finger).
        #[arg(long, default_value_t = 7)]
        sub_factor: u8,
        /// Number of capture stages to collect before committing (defaults to sensor value).
        #[arg(long)]
        stages: Option<u32>,
    },
    /// Wait for a finger and perform an SDCP-authenticated Match-on-Chip identify.
    Verify,
    /// Delete a single slot belonging to this Linux host's partition.
    Delete {
        /// Slot index (0..=9).
        slot: u8,
    },
    /// Delete all slots belonging to this Linux host's partition (preserves Windows Hello slots).
    DeleteAll,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let policy = build_policy(cli.pin_cert_sha256, cli.trusted_ca_der)?;

    let transport = NusbTransport::open_default()
        .context("Failed to open CB2000 (2df0:0007). Is the udev rule installed or are you running with sufficient privileges?")?;
    let host_uuid = derive_linux_host_uuid();
    let dev = Cb2000Device::open(transport, &policy, host_uuid)
        .await
        .context("Failed to initialize CB2000 and establish SDCP session")?;

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel_flag = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel_flag.store(true, Ordering::SeqCst);
            }
        });
    }

    match cli.command {
        Commands::Probe => {
            let caps = dev.capabilities();
            let att = dev.attestation();
            println!("CB2000 Sensor Connected & SDCP Verified!");
            println!("  Protocol Version : {:?}", caps.protocol);
            println!("  Enroll Stages    : {}", caps.enroll_stages);
            println!("  Max Slots        : {}", caps.max_slots);
            println!("  Partition ID     : {}", dev.partition_id());
            println!("  Linux Host UUID  : {}", hex::encode(dev.host_uuid()));
            println!("  Info 0x08        : {}", hex::encode(caps.info_08));
            println!("  Info 0x0A        : {}", hex::encode(caps.info_0a));
            println!("  Info 0x0B        : {}", hex::encode(caps.info_0b));
            println!("  Info 0x0C        : {}", hex::encode(caps.info_0c));
            println!("  Info 0x0D        : {}", hex::encode(caps.info_0d));
            println!("  Model Cert Subj  : {}", att.model_cert_subject);
            println!("  Model Cert Issr  : {}", att.model_cert_issuer);
            println!("  Model Cert SHA256: {}", hex::encode(att.model_cert_sha256));
            println!("  Device Key SHA256: {}", hex::encode(att.device_pubkey_sha256));
            println!("  Firmware Hash    : {}", hex::encode(att.firmware_hash));

            print!("  Testing SDCP Reconnect challenge... ");
            dev.sdcp_reconnect().await?;
            println!("OK!");
        }
        Commands::Slots => {
            let slots = dev.enumerate_slots().await?;
            println!("Sensor Template Slots (Linux partition = {}):", dev.partition_id());
            for s in slots {
                if !s.valid {
                    println!("  [{}] <empty>", s.slot_index);
                } else {
                    let owner = if dev.is_owned_slot(&s) {
                        "LINUX (owned)"
                    } else {
                        "OTHER OS (protected)"
                    };
                    println!(
                        "  [{}] {} | sub_factor={} | partition={:?} | id={}",
                        s.slot_index,
                        owner,
                        s.sub_factor,
                        s.partition_id,
                        hex::encode(&s.enrollment_id[..8])
                    );
                }
            }
        }
        Commands::Enroll { sub_factor, stages } => {
            let stages = stages.unwrap_or_else(|| dev.capabilities().enroll_stages);
            println!("Starting SDCP enrollment (sub_factor={sub_factor}, stages={stages})...");
            let nonce = dev.enroll_begin().await?;
            let mut completed = 0u32;
            while completed < stages {
                println!(
                    "Touch sensor ({}/{})... (Ctrl-C to cancel)",
                    completed + 1,
                    stages
                );
                dev.wait_for_capture(
                    CapturePurpose::Enroll,
                    cancel.clone(),
                    Some(Duration::from_secs(30)),
                    |ev| {
                        if ev == CaptureEvent::RetryNeeded {
                            println!("  Touch rejected; please lift and place finger again.");
                        }
                    },
                )
                .await?;

                let outcome = dev.enroll_accept_sample().await?;
                if outcome.accepted {
                    completed += 1;
                    if completed < stages {
                        println!(
                            "  Stage {completed}/{stages} accepted (meta={}). Lift finger.",
                            hex::encode(outcome.metadata)
                        );
                        dev.wait_for_finger_up(
                            CapturePurpose::Enroll,
                            cancel.clone(),
                            Some(Duration::from_secs(30)),
                        )
                        .await?;
                    } else {
                        println!(
                            "  Stage {completed}/{stages} accepted (meta={}).",
                            hex::encode(outcome.metadata)
                        );
                    }
                } else {
                    println!(
                        "  Sample rejected (code=0x{:02x}); please lift and reposition finger.",
                        outcome.status_code
                    );
                    dev.wait_for_finger_up(
                        CapturePurpose::Enroll,
                        cancel.clone(),
                        Some(Duration::from_secs(30)),
                    )
                    .await?;
                }
            }

            if let Some(dup) = dev.check_duplicate().await? {
                println!(
                    "Warning: finger appears to duplicate existing template (sub_factor={}, id={})",
                    dup.sub_factor,
                    hex::encode(&dup.enrollment_id[..8])
                );
            }

            let enrollment_id = dev.enroll_commit(sub_factor, &nonce).await?;
            println!(
                "Enrollment committed! enrollment_id={}",
                hex::encode(enrollment_id)
            );
        }
        Commands::Verify => {
            println!("Place finger on sensor to verify... (Ctrl-C to cancel)");
            dev.wait_for_capture(
                CapturePurpose::Identify,
                cancel,
                Some(Duration::from_secs(30)),
                |ev| {
                    if ev == CaptureEvent::RetryNeeded {
                        println!("  Touch rejected; please lift and try again.");
                    }
                },
            )
            .await?;

            match dev.identify_captured().await? {
                IdentifyOutcome::Match {
                    sub_factor,
                    enrollment_id,
                    ..
                } => {
                    println!(
                        "MATCH VERIFIED (SDCP MAC OK)! sub_factor={sub_factor} id={}",
                        hex::encode(enrollment_id)
                    );
                }
                IdentifyOutcome::NoMatch => {
                    println!("NO MATCH.");
                }
                IdentifyOutcome::BadCapture { code } => {
                    println!("BAD CAPTURE (code=0x{code:02x}); please retry.");
                }
            }
        }
        Commands::Delete { slot } => {
            dev.delete_owned_slot(slot).await?;
            println!("Deleted Linux-owned slot {slot}.");
        }
        Commands::DeleteAll => {
            let n = dev.delete_all_owned_slots().await?;
            println!("Deleted {n} Linux-owned slot(s). Foreign OS slots were preserved.");
        }
    }

    Ok(())
}

fn build_policy(
    pin_hex: Option<String>,
    ca_path: Option<PathBuf>,
) -> Result<AttestationPolicy> {
    let mut policy = AttestationPolicy::default();
    if let Some(hex_str) = pin_hex {
        let bytes = hex::decode(hex_str.trim()).context("invalid --pin-cert-sha256 hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("--pin-cert-sha256 must be 32 bytes (64 hex chars)"))?;
        policy.pinned_model_cert_sha256.push(arr);
    }
    if let Some(path) = ca_path {
        let der = std::fs::read(&path)
            .with_context(|| format!("failed to read CA cert at {}", path.display()))?;
        policy.trusted_issuer_certs_der.push(der);
    }
    Ok(policy)
}
