//! Pure-Rust, clean-room implementation of Microsoft Secure Device Connection Protocol (SDCP) v1.
//!
//! Security properties:
//! - `#![forbid(unsafe_code)]` (enforced at workspace level)
//! - Ephemeral NIST P-256 ECDH key agreement with OS CSPRNG (`OsRng`)
//! - NIST SP 800-108 Counter Mode KBKDF with HMAC-SHA256
//! - Constant-time MAC verification via `subtle::ConstantTimeEq`
//! - Automatic zeroization of all secret key material on drop via `zeroize::ZeroizeOnDrop`
//! - Full ECDSA P-256 attestation verification of the device Claim (`model_cert -> pk_d -> (h_f || pk_f)`)

use der::{Decode, Encode};
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use spki::ObjectIdentifier;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;
use zeroize::{Zeroize, ZeroizeOnDrop};

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

type HmacSha256 = Hmac<Sha256>;

/// Size of an uncompressed SEC1 NIST P-256 public key (`0x04 || X(32) || Y(32)`).
pub const P256_UNCOMPRESSED_LEN: usize = 65;
/// Size of a raw ECDSA P-256 signature (`r(32) || s(32)`).
pub const P256_RAW_SIG_LEN: usize = 64;
/// Size of an SDCP random nonce, SHA-256 digest, or HMAC-SHA256 tag.
pub const SDCP_DIGEST_LEN: usize = 32;
/// 2-byte SDCP v1 firmware binding hash prefix prepended to `(h_f || pk_f)` before signing `s_d`.
pub const SDCP_FW_BINDING_PREFIX: [u8; 2] = [0xC0, 0x01];
/// Fixed length of the Claim fields following the DER-encoded Model Certificate:
/// `pk_d(65) + pk_f(65) + h_f(32) + s_m(64) + s_d(64) = 290`.
pub const CLAIM_TAIL_LEN: usize =
    P256_UNCOMPRESSED_LEN + P256_UNCOMPRESSED_LEN + SDCP_DIGEST_LEN + P256_RAW_SIG_LEN + P256_RAW_SIG_LEN;

/// Errors returned by SDCP cryptographic operations.
#[derive(Debug, Error)]
pub enum SdcpError {
    #[error("malformed SDCP connect response: {0}")]
    MalformedResponse(&'static str),

    #[error("malformed SDCP claim: {0}")]
    MalformedClaim(&'static str),

    #[error("invalid X.509 model certificate: {0}")]
    InvalidCertificate(String),

    #[error("model certificate rejected by attestation policy: {0}")]
    AttestationPolicyRejected(String),

    #[error("invalid P-256 public key: {0}")]
    InvalidPublicKey(&'static str),

    #[error("invalid ECDSA signature encoding: {0}")]
    InvalidSignature(&'static str),

    #[error("model signature (s_m) verification over pk_d failed")]
    ModelSignatureInvalid,

    #[error("device signature (s_d) verification over (h_f || pk_f) failed")]
    DeviceSignatureInvalid,

    #[error("SDCP connect MAC verification failed")]
    ConnectMacMismatch,

    #[error("SDCP reconnect MAC verification failed")]
    ReconnectMacMismatch,

    #[error("SDCP authorized identify MAC verification failed (possible spoofing or replay)")]
    IdentifyMacMismatch,

    #[error("HMAC/KDF internal error")]
    CryptoInternal,
}

/// Attestation verification policy for the sensor's X.509 Model Certificate and device key.
#[derive(Debug, Clone, Default)]
pub struct AttestationPolicy {
    /// If non-empty, the SHA-256 fingerprint of the DER-encoded Model Certificate must match
    /// one of the entries in this allowlist (Trust-On-First-Use or explicit pinning).
    pub pinned_model_cert_sha256: Vec<[u8; 32]>,
    /// If non-empty, the SHA-256 fingerprint of the sensor's per-device public key (`pk_d`)
    /// must match one of the entries in this allowlist (binds to a specific physical sensor).
    pub pinned_device_pubkey_sha256: Vec<[u8; 32]>,
    /// If non-empty, the Model Certificate's DER signature must verify against one of these
    /// trusted issuing CA certificates (e.g., Windows Hello Secure Devices CA).
    pub trusted_issuer_certs_der: Vec<Vec<u8>>,
}

/// Raw Connect Response fields received from the sensor.
#[derive(Debug, Clone)]
pub struct ConnectResponse {
    pub device_random: [u8; SDCP_DIGEST_LEN],
    pub claim: Vec<u8>,
    pub mac: [u8; SDCP_DIGEST_LEN],
}

impl ConnectResponse {
    /// Parse the CB2000 length-prefixed wire format:
    /// `[u16_le(len_rd) || r_d || u16_le(len_claim) || claim || u16_le(len_mac) || mac]`.
    pub fn from_wire(buf: &[u8]) -> Result<Self, SdcpError> {
        let mut cursor = 0usize;

        let rd_slice = read_u16_prefixed(buf, &mut cursor)
            .ok_or(SdcpError::MalformedResponse("truncated device_random"))?;
        let device_random: [u8; SDCP_DIGEST_LEN] = rd_slice
            .try_into()
            .map_err(|_| SdcpError::MalformedResponse("device_random must be 32 bytes"))?;

        let claim_slice = read_u16_prefixed(buf, &mut cursor)
            .ok_or(SdcpError::MalformedResponse("truncated claim"))?;
        if claim_slice.len() <= CLAIM_TAIL_LEN {
            return Err(SdcpError::MalformedClaim("claim shorter than fixed tail"));
        }

        let mac_slice = read_u16_prefixed(buf, &mut cursor)
            .ok_or(SdcpError::MalformedResponse("truncated connect mac"))?;
        let mac: [u8; SDCP_DIGEST_LEN] = mac_slice
            .try_into()
            .map_err(|_| SdcpError::MalformedResponse("connect mac must be 32 bytes"))?;

        Ok(Self {
            device_random,
            claim: claim_slice.to_vec(),
            mac,
        })
    }
}

/// Parsed fields of an SDCP device Claim.
#[derive(Debug, Clone)]
pub struct ParsedClaim<'a> {
    pub model_cert_der: &'a [u8],
    pub pk_d: &'a [u8; P256_UNCOMPRESSED_LEN],
    pub pk_f: &'a [u8; P256_UNCOMPRESSED_LEN],
    pub h_f: &'a [u8; SDCP_DIGEST_LEN],
    pub s_m: &'a [u8; P256_RAW_SIG_LEN],
    pub s_d: &'a [u8; P256_RAW_SIG_LEN],
}

impl<'a> ParsedClaim<'a> {
    /// Parse a raw SDCP claim by reading the ASN.1 DER length of the leading X.509 certificate.
    pub fn parse(claim: &'a [u8]) -> Result<Self, SdcpError> {
        let cert_len = der_tlv_total_len(claim)
            .ok_or(SdcpError::MalformedClaim("invalid leading DER SEQUENCE header"))?;
        if claim.len() != cert_len + CLAIM_TAIL_LEN {
            return Err(SdcpError::MalformedClaim(
                "claim total length does not match cert_len + 290",
            ));
        }

        let model_cert_der = &claim[..cert_len];
        let tail = &claim[cert_len..];

        let pk_d: &[u8; P256_UNCOMPRESSED_LEN] = tail[0..65]
            .try_into()
            .map_err(|_| SdcpError::MalformedClaim("pk_d slice"))?;
        let pk_f: &[u8; P256_UNCOMPRESSED_LEN] = tail[65..130]
            .try_into()
            .map_err(|_| SdcpError::MalformedClaim("pk_f slice"))?;
        let h_f: &[u8; SDCP_DIGEST_LEN] = tail[130..162]
            .try_into()
            .map_err(|_| SdcpError::MalformedClaim("h_f slice"))?;
        let s_m: &[u8; P256_RAW_SIG_LEN] = tail[162..226]
            .try_into()
            .map_err(|_| SdcpError::MalformedClaim("s_m slice"))?;
        let s_d: &[u8; P256_RAW_SIG_LEN] = tail[226..290]
            .try_into()
            .map_err(|_| SdcpError::MalformedClaim("s_d slice"))?;

        Ok(Self {
            model_cert_der,
            pk_d,
            pk_f,
            h_f,
            s_m,
            s_d,
        })
    }
}

/// Verified attestation details extracted from a successful SDCP Connect handshake.
#[derive(Debug, Clone)]
pub struct DeviceAttestation {
    pub model_cert_subject: String,
    pub model_cert_issuer: String,
    pub model_cert_sha256: [u8; SDCP_DIGEST_LEN],
    pub firmware_hash: [u8; SDCP_DIGEST_LEN],
    pub device_pubkey_uncompressed: [u8; P256_UNCOMPRESSED_LEN],
    pub device_pubkey_sha256: [u8; SDCP_DIGEST_LEN],
}

/// Ephemeral client state for initiating an SDCP Connect handshake.
pub struct SdcpClientHandshake {
    host_random: [u8; SDCP_DIGEST_LEN],
    ephemeral_secret: EphemeralSecret,
    host_pubkey_uncompressed: [u8; P256_UNCOMPRESSED_LEN],
}

impl SdcpClientHandshake {
    /// Create a new SDCP Connect handshake using OS CSPRNG entropy.
    pub fn new() -> Result<Self, SdcpError> {
        let mut host_random = [0u8; SDCP_DIGEST_LEN];
        OsRng.fill_bytes(&mut host_random);

        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let pubkey = PublicKey::from(&ephemeral_secret);
        let encoded = pubkey.to_encoded_point(false);
        let host_pubkey_uncompressed: [u8; P256_UNCOMPRESSED_LEN] = encoded
            .as_bytes()
            .try_into()
            .map_err(|_| SdcpError::InvalidPublicKey("uncompressed host pubkey length"))?;

        Ok(Self {
            host_random,
            ephemeral_secret,
            host_pubkey_uncompressed,
        })
    }

    pub fn host_random(&self) -> &[u8; SDCP_DIGEST_LEN] {
        &self.host_random
    }

    pub fn host_pubkey_uncompressed(&self) -> &[u8; P256_UNCOMPRESSED_LEN] {
        &self.host_pubkey_uncompressed
    }

    /// Serialize the CB2000 Connect Request wire payload (101 bytes):
    /// `[u16_le(32) || r_h(32) || u16_le(65) || pk_h(65)]`.
    pub fn to_wire_request(&self) -> [u8; 2 + SDCP_DIGEST_LEN + 2 + P256_UNCOMPRESSED_LEN] {
        let mut out = [0u8; 2 + SDCP_DIGEST_LEN + 2 + P256_UNCOMPRESSED_LEN];
        out[0..2].copy_from_slice(&(SDCP_DIGEST_LEN as u16).to_le_bytes());
        out[2..34].copy_from_slice(&self.host_random);
        out[34..36].copy_from_slice(&(P256_UNCOMPRESSED_LEN as u16).to_le_bytes());
        out[36..101].copy_from_slice(&self.host_pubkey_uncompressed);
        out
    }

    /// Complete the SDCP Connect handshake:
    /// 1. Parse and validate the Claim & X.509 Model Certificate.
    /// 2. Verify ECDSA signature `s_m` over `SHA-256(pk_d)` using the Model Certificate public key.
    /// 3. Verify ECDSA signature `s_d` over `SHA-256(h_f || pk_f)` using `pk_d`.
    /// 4. Perform ECDH P-256 with `pk_f`, derive `master_secret`, `m_k`, `s_k`.
    /// 5. Constant-time verify `connect_mac == HMAC-SHA256(m_k, "connect\0" || SHA-256(claim))`.
    pub fn complete(
        self,
        response: &ConnectResponse,
        policy: &AttestationPolicy,
    ) -> Result<(SdcpSession, DeviceAttestation), SdcpError> {
        let parsed = ParsedClaim::parse(&response.claim)?;

        // 1. Parse X.509 Model Certificate and extract its P-256 verifying key.
        let model_cert = Certificate::from_der(parsed.model_cert_der)
            .map_err(|e| SdcpError::InvalidCertificate(e.to_string()))?;

        let cert_sha256: [u8; 32] = Sha256::digest(parsed.model_cert_der).into();
        let pk_d_sha256: [u8; 32] = Sha256::digest(parsed.pk_d).into();

        // Enforce optional Model Certificate SHA-256 pin list.
        if !policy.pinned_model_cert_sha256.is_empty()
            && !policy
                .pinned_model_cert_sha256
                .iter()
                .any(|pin| bool::from(pin.ct_eq(&cert_sha256)))
        {
            return Err(SdcpError::AttestationPolicyRejected(format!(
                "model cert sha256 {} not in pinned allowlist",
                hex::encode(cert_sha256)
            )));
        }

        // Enforce optional per-device public key (pk_d) SHA-256 pin list.
        if !policy.pinned_device_pubkey_sha256.is_empty()
            && !policy
                .pinned_device_pubkey_sha256
                .iter()
                .any(|pin| bool::from(pin.ct_eq(&pk_d_sha256)))
        {
            return Err(SdcpError::AttestationPolicyRejected(format!(
                "device pubkey sha256 {} not in pinned allowlist",
                hex::encode(pk_d_sha256)
            )));
        }

        // Enforce optional issuing CA signature verification.
        if !policy.trusted_issuer_certs_der.is_empty() {
            verify_cert_against_issuers(&model_cert, &policy.trusted_issuer_certs_der)?;
        }

        let model_vk = extract_p256_verifying_key_from_cert(&model_cert)?;

        // 2. Verify s_m = ECDSA_Sign(sk_m, SHA-256(pk_d)).
        let sig_m = Signature::from_slice(parsed.s_m)
            .map_err(|_| SdcpError::InvalidSignature("s_m invalid raw signature"))?;
        model_vk
            .verify_prehash(&pk_d_sha256, &sig_m)
            .map_err(|_| SdcpError::ModelSignatureInvalid)?;

        // 3. Verify s_d = ECDSA_Sign(sk_d, SHA-256([0xC0, 0x01] || h_f || pk_f)).
        let pk_d_point = EncodedPoint::from_bytes(parsed.pk_d)
            .map_err(|_| SdcpError::InvalidPublicKey("pk_d SEC1 encoding"))?;
        let pk_d_vk = VerifyingKey::from_encoded_point(&pk_d_point)
            .map_err(|_| SdcpError::InvalidPublicKey("pk_d not on P-256"))?;

        let mut fw_hasher = Sha256::new();
        fw_hasher.update(SDCP_FW_BINDING_PREFIX);
        fw_hasher.update(parsed.h_f);
        fw_hasher.update(parsed.pk_f);
        let fw_binding_hash = fw_hasher.finalize();

        let sig_d = Signature::from_slice(parsed.s_d)
            .map_err(|_| SdcpError::InvalidSignature("s_d invalid raw signature"))?;
        pk_d_vk
            .verify_prehash(&fw_binding_hash, &sig_d)
            .map_err(|_| SdcpError::DeviceSignatureInvalid)?;

        // 4. ECDH P-256 with firmware ephemeral public key pk_f.
        let pk_f_key = PublicKey::from_sec1_bytes(parsed.pk_f)
            .map_err(|_| SdcpError::InvalidPublicKey("pk_f not a valid P-256 point"))?;
        let shared = self.ephemeral_secret.diffie_hellman(&pk_f_key);
        let mut shared_bytes = [0u8; SDCP_DIGEST_LEN];
        shared_bytes.copy_from_slice(&shared.raw_secret_bytes()[..]);

        // Derive master_secret = KBKDF(shared_secret, "master secret", r_h || r_d, 32).
        let mut context = [0u8; SDCP_DIGEST_LEN * 2];
        context[..SDCP_DIGEST_LEN].copy_from_slice(&self.host_random);
        context[SDCP_DIGEST_LEN..].copy_from_slice(&response.device_random);

        let mut master_secret = [0u8; SDCP_DIGEST_LEN];
        let kdf_res = kbkdf_counter_hmac_sha256(
            &shared_bytes,
            b"master secret",
            &context,
            &mut master_secret,
        );
        shared_bytes.zeroize();
        context.zeroize();
        kdf_res?;

        // Derive (m_k || s_k) = KBKDF(master_secret, "application keys", "", 64).
        let mut app_keys = [0u8; SDCP_DIGEST_LEN * 2];
        let app_res =
            kbkdf_counter_hmac_sha256(&master_secret, b"application keys", &[], &mut app_keys);
        if let Err(e) = app_res {
            master_secret.zeroize();
            app_keys.zeroize();
            return Err(e);
        }

        let mut mac_key = [0u8; SDCP_DIGEST_LEN];
        let mut sym_key = [0u8; SDCP_DIGEST_LEN];
        mac_key.copy_from_slice(&app_keys[..SDCP_DIGEST_LEN]);
        sym_key.copy_from_slice(&app_keys[SDCP_DIGEST_LEN..]);
        app_keys.zeroize();

        // 5. Verify Connect MAC: HMAC-SHA256(m_k, "connect\0" || SHA-256(claim)).
        let claim_hash: [u8; SDCP_DIGEST_LEN] = Sha256::digest(&response.claim).into();
        let mut expected_mac = sdcp_mac(&mac_key, b"connect", &[&claim_hash])?;
        let mac_ok = bool::from(expected_mac.ct_eq(&response.mac));
        expected_mac.zeroize();

        if !mac_ok {
            master_secret.zeroize();
            mac_key.zeroize();
            sym_key.zeroize();
            return Err(SdcpError::ConnectMacMismatch);
        }

        let attestation = DeviceAttestation {
            model_cert_subject: model_cert.tbs_certificate.subject.to_string(),
            model_cert_issuer: model_cert.tbs_certificate.issuer.to_string(),
            model_cert_sha256: cert_sha256,
            firmware_hash: *parsed.h_f,
            device_pubkey_uncompressed: *parsed.pk_d,
            device_pubkey_sha256: pk_d_sha256,
        };

        let session = SdcpSession {
            master_secret,
            mac_key,
            sym_key,
        };

        Ok((session, attestation))
    }
}

/// Active authenticated SDCP session holding derived session keys.
/// All keys are zeroized from memory automatically when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SdcpSession {
    master_secret: [u8; SDCP_DIGEST_LEN],
    mac_key: [u8; SDCP_DIGEST_LEN],
    sym_key: [u8; SDCP_DIGEST_LEN],
}

impl SdcpSession {
    /// Generate a fresh 32-byte cryptographically secure random nonce.
    pub fn fresh_nonce() -> [u8; SDCP_DIGEST_LEN] {
        let mut nonce = [0u8; SDCP_DIGEST_LEN];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Build a CB2000 Reconnect Request wire payload (34 bytes): `[u16_le(32) || host_random(32)]`.
    pub fn build_reconnect_request(
        host_random: &[u8; SDCP_DIGEST_LEN],
    ) -> [u8; 2 + SDCP_DIGEST_LEN] {
        let mut out = [0u8; 2 + SDCP_DIGEST_LEN];
        out[0..2].copy_from_slice(&(SDCP_DIGEST_LEN as u16).to_le_bytes());
        out[2..34].copy_from_slice(host_random);
        out
    }

    /// Verify a Reconnect response MAC in constant time:
    /// `HMAC-SHA256(m_k, "reconnect\0" || host_random)`.
    pub fn verify_reconnect(
        &self,
        host_random: &[u8; SDCP_DIGEST_LEN],
        device_mac: &[u8; SDCP_DIGEST_LEN],
    ) -> Result<(), SdcpError> {
        let mut expected = sdcp_mac(&self.mac_key, b"reconnect", &[host_random])?;
        let ok = bool::from(expected.ct_eq(device_mac));
        expected.zeroize();
        if ok {
            Ok(())
        } else {
            Err(SdcpError::ReconnectMacMismatch)
        }
    }

    /// Compute the SDCP Enrollment Authorization MAC (`m_a`) for `EnrollCommit`:
    /// `HMAC-SHA256(m_k, "enroll\0" || device_enroll_nonce)`.
    pub fn compute_enroll_mac(
        &self,
        device_enroll_nonce: &[u8; SDCP_DIGEST_LEN],
    ) -> Result<[u8; SDCP_DIGEST_LEN], SdcpError> {
        sdcp_mac(&self.mac_key, b"enroll", &[device_enroll_nonce])
    }

    /// Verify an Authorized Identify MAC in constant time:
    /// `HMAC-SHA256(m_k, "identify\0" || host_identify_nonce || matched_enrollment_id)`.
    pub fn verify_identify_mac(
        &self,
        host_identify_nonce: &[u8; SDCP_DIGEST_LEN],
        matched_enrollment_id: &[u8; SDCP_DIGEST_LEN],
        device_mac: &[u8; SDCP_DIGEST_LEN],
    ) -> Result<(), SdcpError> {
        let mut expected = sdcp_mac(
            &self.mac_key,
            b"identify",
            &[host_identify_nonce, matched_enrollment_id],
        )?;
        let ok = bool::from(expected.ct_eq(device_mac));
        expected.zeroize();
        if ok {
            Ok(())
        } else {
            Err(SdcpError::IdentifyMacMismatch)
        }
    }

    /// Expose symmetric key length check (keeps `sym_key` intentionally private/encapsulated).
    pub fn has_symmetric_key(&self) -> bool {
        self.sym_key.len() == SDCP_DIGEST_LEN
    }
}

/// NIST SP 800-108 Counter Mode KBKDF with HMAC-SHA256 as specified by SDCP v1:
/// `K(i) = HMAC-SHA256(key, u32_be(i) || label || 0x00 || context || u32_be(L_bits))`.
pub fn kbkdf_counter_hmac_sha256(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), SdcpError> {
    if key.len() < SDCP_DIGEST_LEN || out.is_empty() || out.len() > 0x1fff_ffff {
        return Err(SdcpError::CryptoInternal);
    }

    let l_bits = ((out.len() as u32) * 8).to_be_bytes();
    let num_blocks = out.len().div_ceil(SDCP_DIGEST_LEN);

    for block_idx in 0..num_blocks {
        let counter = ((block_idx as u32) + 1).to_be_bytes();
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SdcpError::CryptoInternal)?;
        mac.update(&counter);
        mac.update(label);
        mac.update(&[0x00]);
        if !context.is_empty() {
            mac.update(context);
        }
        mac.update(&l_bits);
        let mut digest = mac.finalize().into_bytes();

        let start = block_idx * SDCP_DIGEST_LEN;
        let take = (out.len() - start).min(SDCP_DIGEST_LEN);
        out[start..start + take].copy_from_slice(&digest[..take]);
        digest.zeroize();
    }

    Ok(())
}

/// SDCP domain-separated HMAC-SHA256: `HMAC-SHA256(key, label || 0x00 || chunks...)`.
pub fn sdcp_mac(
    key: &[u8; SDCP_DIGEST_LEN],
    label: &[u8],
    chunks: &[&[u8]],
) -> Result<[u8; SDCP_DIGEST_LEN], SdcpError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SdcpError::CryptoInternal)?;
    mac.update(label);
    mac.update(&[0x00]);
    for chunk in chunks {
        mac.update(chunk);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn read_u16_prefixed<'a>(buf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let header_end = cursor.checked_add(2)?;
    if header_end > buf.len() {
        return None;
    }
    let len = u16::from_le_bytes([buf[*cursor], buf[*cursor + 1]]) as usize;
    let body_end = header_end.checked_add(len)?;
    if body_end > buf.len() {
        return None;
    }
    let slice = &buf[header_end..body_end];
    *cursor = body_end;
    Some(slice)
}

/// Compute the total byte length of a single ASN.1 DER TLV element (must start with SEQUENCE 0x30).
fn der_tlv_total_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != 0x30 {
        return None;
    }
    let first_len = buf[1];
    if first_len & 0x80 == 0 {
        let total = 2 + (first_len as usize);
        (total <= buf.len()).then_some(total)
    } else {
        let num_len_bytes = (first_len & 0x7f) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 || 2 + num_len_bytes > buf.len() {
            return None;
        }
        let mut content_len = 0usize;
        for &b in &buf[2..2 + num_len_bytes] {
            content_len = (content_len << 8) | (b as usize);
        }
        let total = 2usize
            .checked_add(num_len_bytes)?
            .checked_add(content_len)?;
        (total <= buf.len()).then_some(total)
    }
}

fn extract_p256_verifying_key_from_cert(cert: &Certificate) -> Result<VerifyingKey, SdcpError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(SdcpError::InvalidCertificate(format!(
            "unsupported SPKI algorithm OID {} (expected id-ecPublicKey)",
            spki.algorithm.oid
        )));
    }
    let curve_oid: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| SdcpError::InvalidCertificate("missing EC curve parameters OID".into()))?
        .decode_as()
        .map_err(|_| SdcpError::InvalidCertificate("invalid EC curve parameters OID".into()))?;
    if curve_oid != OID_SECP256R1 {
        return Err(SdcpError::InvalidCertificate(format!(
            "unsupported EC curve OID {curve_oid} (expected secp256r1)"
        )));
    }

    let key_bytes = spki.subject_public_key.raw_bytes();
    let point = EncodedPoint::from_bytes(key_bytes)
        .map_err(|_| SdcpError::InvalidCertificate("model cert SPKI is not SEC1 P-256".into()))?;
    VerifyingKey::from_encoded_point(&point)
        .map_err(|_| SdcpError::InvalidCertificate("model cert SPKI is not on P-256 curve".into()))
}

fn cert_is_ca(cert: &Certificate) -> bool {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    exts.iter().any(|ext| {
        ext.extn_id == OID_BASIC_CONSTRAINTS
            && BasicConstraints::from_der(ext.extn_value.as_bytes()).is_ok_and(|bc| bc.ca)
    })
}

fn verify_cert_against_issuers(
    leaf: &Certificate,
    issuers_der: &[Vec<u8>],
) -> Result<(), SdcpError> {
    if leaf.signature_algorithm != leaf.tbs_certificate.signature {
        return Err(SdcpError::InvalidCertificate(
            "leaf cert outer signatureAlgorithm does not match tbsCertificate.signature".into(),
        ));
    }
    if leaf.signature_algorithm.oid != OID_ECDSA_WITH_SHA256 {
        return Err(SdcpError::InvalidCertificate(format!(
            "unsupported leaf cert signature OID {} (only ecdsa-with-SHA256 is supported)",
            leaf.signature_algorithm.oid
        )));
    }

    let tbs_der = leaf
        .tbs_certificate
        .to_der()
        .map_err(|e| SdcpError::InvalidCertificate(format!("re-encode tbs: {e}")))?;
    let sig_der = leaf.signature.raw_bytes();
    let sig = Signature::from_der(sig_der)
        .map_err(|_| SdcpError::InvalidCertificate("leaf cert signature is not DER ECDSA".into()))?;
    let tbs_hash = Sha256::digest(&tbs_der);

    for issuer_der in issuers_der {
        let Ok(issuer) = Certificate::from_der(issuer_der) else {
            continue;
        };
        if issuer.tbs_certificate.subject != leaf.tbs_certificate.issuer {
            continue;
        }
        if !cert_is_ca(&issuer) {
            continue;
        }
        let Ok(issuer_vk) = extract_p256_verifying_key_from_cert(&issuer) else {
            continue;
        };
        if issuer_vk.verify_prehash(&tbs_hash, &sig).is_ok() {
            return Ok(());
        }
    }

    Err(SdcpError::AttestationPolicyRejected(
        "model certificate did not verify against any configured trusted issuer CA".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    /// Build a minimal valid self-signed DER X.509 v3 certificate containing `model_vk` for tests.
    fn build_test_x509_der(model_sk: &SigningKey, is_ca: bool) -> Vec<u8> {
        use der::asn1::{BitString, OctetString};
        use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
        use x509_cert::ext::Extension;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::{Time, Validity};
        use x509_cert::TbsCertificate;

        let ecdsa_sha256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        let ec_pubkey_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        let secp256r1_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

        let sig_alg = AlgorithmIdentifierOwned {
            oid: ecdsa_sha256_oid,
            parameters: None,
        };
        let spki_alg = AlgorithmIdentifierOwned {
            oid: ec_pubkey_oid,
            parameters: Some(der::Any::encode_from(&secp256r1_oid).unwrap()),
        };

        let pub_bytes = model_sk.verifying_key().to_encoded_point(false);
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_alg,
            subject_public_key: BitString::from_bytes(pub_bytes.as_bytes()).unwrap(),
        };

        let name: Name = "CN=CB2000 Test Model Cert".parse().unwrap();
        let validity = Validity {
            not_before: Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(1_700_000_000))
                    .unwrap(),
            ),
            not_after: Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(1_900_000_000))
                    .unwrap(),
            ),
        };

        let extensions = if is_ca {
            let bc = BasicConstraints {
                ca: true,
                path_len_constraint: None,
            };
            let bc_der = bc.to_der().unwrap();
            Some(vec![Extension {
                extn_id: OID_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: OctetString::new(bc_der).unwrap(),
            }])
        } else {
            None
        };

        let tbs = TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: SerialNumber::new(&[1u8]).unwrap(),
            signature: sig_alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions,
        };

        let tbs_der = tbs.to_der().unwrap();
        let tbs_hash = Sha256::digest(&tbs_der);
        let sig: Signature = model_sk.sign_prehash(&tbs_hash).unwrap();
        let sig_der = sig.to_der();

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(sig_der.as_bytes()).unwrap(),
        };
        cert.to_der().unwrap()
    }

    fn simulate_device_connect(
        req_wire: &[u8],
        model_sk: &SigningKey,
        model_cert_der: &[u8],
    ) -> (Vec<u8>, [u8; 32]) {
        assert_eq!(req_wire.len(), 101);
        let host_random = &req_wire[2..34];
        let host_pubkey = PublicKey::from_sec1_bytes(&req_wire[36..101]).unwrap();

        let device_sk = SigningKey::random(&mut OsRng);
        let pk_d: [u8; 65] = device_sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();

        let fw_ephemeral = EphemeralSecret::random(&mut OsRng);
        let pk_f: [u8; 65] = PublicKey::from(&fw_ephemeral)
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();

        let h_f = [0xABu8; 32];

        // s_m = Sign(model_sk, SHA256(pk_d))
        let s_m: Signature = model_sk.sign_prehash(&Sha256::digest(pk_d)).unwrap();
        // s_d = Sign(device_sk, SHA256([0xC0, 0x01] || h_f || pk_f))
        let mut fw_hasher = Sha256::new();
        fw_hasher.update(SDCP_FW_BINDING_PREFIX);
        fw_hasher.update(h_f);
        fw_hasher.update(pk_f);
        let s_d: Signature = device_sk.sign_prehash(&fw_hasher.finalize()).unwrap();

        let mut claim = Vec::new();
        claim.extend_from_slice(model_cert_der);
        claim.extend_from_slice(&pk_d);
        claim.extend_from_slice(&pk_f);
        claim.extend_from_slice(&h_f);
        claim.extend_from_slice(&s_m.to_bytes());
        claim.extend_from_slice(&s_d.to_bytes());

        let mut r_d = [0u8; 32];
        OsRng.fill_bytes(&mut r_d);

        let shared = fw_ephemeral.diffie_hellman(&host_pubkey);
        let mut ctx = [0u8; 64];
        ctx[..32].copy_from_slice(host_random);
        ctx[32..].copy_from_slice(&r_d);

        let mut ms = [0u8; 32];
        kbkdf_counter_hmac_sha256(&shared.raw_secret_bytes()[..], b"master secret", &ctx, &mut ms)
            .unwrap();
        let mut app = [0u8; 64];
        kbkdf_counter_hmac_sha256(&ms, b"application keys", &[], &mut app).unwrap();
        let m_k: [u8; 32] = app[..32].try_into().unwrap();

        let claim_hash: [u8; 32] = Sha256::digest(&claim).into();
        let mac = sdcp_mac(&m_k, b"connect", &[&claim_hash]).unwrap();

        let mut wire = Vec::new();
        wire.extend_from_slice(&(32u16).to_le_bytes());
        wire.extend_from_slice(&r_d);
        wire.extend_from_slice(&(claim.len() as u16).to_le_bytes());
        wire.extend_from_slice(&claim);
        wire.extend_from_slice(&(32u16).to_le_bytes());
        wire.extend_from_slice(&mac);
        (wire, m_k)
    }

    #[test]
    fn full_sdcp_handshake_enroll_identify_reconnect_roundtrip() {
        let model_sk = SigningKey::random(&mut OsRng);
        let model_cert_der = build_test_x509_der(&model_sk, true);

        let hs = SdcpClientHandshake::new().unwrap();
        let req = hs.to_wire_request();
        let (resp_wire, dev_mk) = simulate_device_connect(&req, &model_sk, &model_cert_der);
        let resp = ConnectResponse::from_wire(&resp_wire).unwrap();

        let policy = AttestationPolicy {
            pinned_model_cert_sha256: vec![Sha256::digest(&model_cert_der).into()],
            pinned_device_pubkey_sha256: Vec::new(),
            trusted_issuer_certs_der: vec![model_cert_der.clone()],
        };
        let (session, att) = hs.complete(&resp, &policy).unwrap();
        assert_eq!(att.firmware_hash, [0xABu8; 32]);
        assert!(session.has_symmetric_key());

        // Reconnect verification
        let r_h2 = SdcpSession::fresh_nonce();
        let reconn_mac = sdcp_mac(&dev_mk, b"reconnect", &[&r_h2]).unwrap();
        session.verify_reconnect(&r_h2, &reconn_mac).unwrap();

        // Enroll MAC matches device expectation
        let enroll_nonce = [0x42u8; 32];
        let enroll_mac = session.compute_enroll_mac(&enroll_nonce).unwrap();
        let dev_expected_enroll = sdcp_mac(&dev_mk, b"enroll", &[&enroll_nonce]).unwrap();
        assert_eq!(enroll_mac, dev_expected_enroll);

        // Authorized Identify MAC verifies
        let id_nonce = SdcpSession::fresh_nonce();
        let id_mac = sdcp_mac(&dev_mk, b"identify", &[&id_nonce, &enroll_mac]).unwrap();
        session
            .verify_identify_mac(&id_nonce, &enroll_mac, &id_mac)
            .unwrap();

        // Replay with different nonce MUST fail
        let other_nonce = SdcpSession::fresh_nonce();
        assert!(matches!(
            session.verify_identify_mac(&other_nonce, &enroll_mac, &id_mac),
            Err(SdcpError::IdentifyMacMismatch)
        ));

        // Tampered MAC MUST fail
        let mut bad_mac = id_mac;
        bad_mac[0] ^= 0x01;
        assert!(matches!(
            session.verify_identify_mac(&id_nonce, &enroll_mac, &bad_mac),
            Err(SdcpError::IdentifyMacMismatch)
        ));
    }

    #[test]
    fn rejects_tampered_claim_signature() {
        let model_sk = SigningKey::random(&mut OsRng);
        let model_cert_der = build_test_x509_der(&model_sk, false);

        let hs = SdcpClientHandshake::new().unwrap();
        let req = hs.to_wire_request();
        let (resp_wire, _dev_mk) = simulate_device_connect(&req, &model_sk, &model_cert_der);
        let mut resp = ConnectResponse::from_wire(&resp_wire).unwrap();

        // Flip a bit in s_d (last 64 bytes of claim)
        let last = resp.claim.len() - 1;
        resp.claim[last] ^= 0xFF;

        // Even with permissive policy, signature MUST fail
        assert!(matches!(
            hs.complete(&resp, &AttestationPolicy::default()),
            Err(SdcpError::DeviceSignatureInvalid)
        ));
    }

    #[test]
    fn rejects_swapped_device_pubkey_and_non_ca_issuer() {
        let model_sk = SigningKey::random(&mut OsRng);
        let leaf_cert_der = build_test_x509_der(&model_sk, false);

        // First sensor succeeds and yields a concrete pk_d hash.
        let hs1 = SdcpClientHandshake::new().unwrap();
        let (resp1_wire, _) = simulate_device_connect(&hs1.to_wire_request(), &model_sk, &leaf_cert_der);
        let resp1 = ConnectResponse::from_wire(&resp1_wire).unwrap();
        let (_, att1) = hs1.complete(&resp1, &AttestationPolicy::default()).unwrap();

        // Second physical sensor of the SAME model has a different pk_d -> MUST be rejected.
        let hs2 = SdcpClientHandshake::new().unwrap();
        let (resp2_wire, _) = simulate_device_connect(&hs2.to_wire_request(), &model_sk, &leaf_cert_der);
        let resp2 = ConnectResponse::from_wire(&resp2_wire).unwrap();
        let strict_policy = AttestationPolicy {
            pinned_model_cert_sha256: vec![att1.model_cert_sha256],
            pinned_device_pubkey_sha256: vec![att1.device_pubkey_sha256],
            trusted_issuer_certs_der: Vec::new(),
        };
        assert!(matches!(
            hs2.complete(&resp2, &strict_policy),
            Err(SdcpError::AttestationPolicyRejected(_))
        ));

        // A non-CA cert (missing BasicConstraints ca=true) MUST NOT be accepted as a trusted issuer.
        let hs3 = SdcpClientHandshake::new().unwrap();
        let (resp3_wire, _) = simulate_device_connect(&hs3.to_wire_request(), &model_sk, &leaf_cert_der);
        let resp3 = ConnectResponse::from_wire(&resp3_wire).unwrap();
        let ca_policy = AttestationPolicy {
            pinned_model_cert_sha256: Vec::new(),
            pinned_device_pubkey_sha256: Vec::new(),
            trusted_issuer_certs_der: vec![leaf_cert_der],
        };
        assert!(matches!(
            hs3.complete(&resp3, &ca_policy),
            Err(SdcpError::AttestationPolicyRejected(_))
        ));
    }
}
