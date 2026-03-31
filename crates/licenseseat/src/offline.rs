//! Offline validation helpers.
//!
//! This module handles both legacy offline tokens and the newer machine-file
//! flow used by the current API and C++ SDK.

use crate::error::{Error, Result};
use crate::models::{
    Entitlement, LicenseResponse, MachineFile, MachineFilePayload, OfflineTokenResponse, Product,
    SigningKeyResponse, ValidationResult,
};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

struct ParsedMachineFileEnvelope {
    enc: String,
    sig: String,
    alg: String,
}

/// Verify an offline token's signature.
pub fn verify_token(
    token: &OfflineTokenResponse,
    signing_key: &SigningKeyResponse,
) -> Result<bool> {
    verify_ed25519_signature(
        token.canonical.as_bytes(),
        &token.signature.value,
        &signing_key.public_key,
        false,
    )
}

/// Check if an offline token is currently valid (not expired, not before).
pub fn check_token_validity(token: &OfflineTokenResponse) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let payload = &token.token;

    if now < payload.nbf {
        return Err(Error::OfflineVerificationFailed(
            "Token is not yet valid (nbf)".into(),
        ));
    }

    if now > payload.exp {
        return Err(Error::OfflineTokenExpired);
    }

    if let Some(license_exp) = payload.license_expires_at {
        if now > license_exp {
            return Err(Error::OfflineVerificationFailed(
                "License has expired".into(),
            ));
        }
    }

    Ok(())
}

/// Convert an offline token to a `ValidationResult`.
pub fn token_to_validation_result(token: &OfflineTokenResponse) -> ValidationResult {
    let payload = &token.token;

    let entitlements: Vec<Entitlement> = payload
        .entitlements
        .iter()
        .map(|e| Entitlement {
            key: e.key.clone(),
            expires_at: e
                .expires_at
                .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0)),
            metadata: None,
        })
        .collect();

    ValidationResult {
        object: "validation_result".into(),
        valid: true,
        code: None,
        message: None,
        warnings: None,
        license: LicenseResponse {
            object: "license".into(),
            key: payload.license_key.clone(),
            status: "active".into(),
            starts_at: None,
            expires_at: payload
                .license_expires_at
                .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0)),
            mode: payload.mode.clone(),
            plan_key: payload.plan_key.clone(),
            seat_limit: payload.seat_limit,
            active_seats: 0,
            active_entitlements: entitlements,
            metadata: payload.metadata.clone(),
            product: Product {
                slug: payload.product_slug.clone(),
                name: payload.product_slug.clone(),
            },
        },
        activation: None,
        offline: true,
    }
}

/// Verify and decrypt a machine file.
pub fn verify_machine_file(
    machine_file: &MachineFile,
    license_key: &str,
    fingerprint: &str,
    public_key_b64: &str,
) -> Result<MachineFilePayload> {
    if license_key.is_empty() {
        return Err(Error::Configuration("license_key is required".into()));
    }
    if fingerprint.is_empty() {
        return Err(Error::Configuration("fingerprint is required".into()));
    }
    if public_key_b64.is_empty() {
        return Err(Error::Configuration("public_key is required".into()));
    }

    let envelope = parse_machine_file_envelope(&machine_file.certificate)?;
    if !envelope.alg.is_empty() && envelope.alg != "aes-256-gcm+ed25519" {
        return Err(Error::OfflineVerificationFailed(
            "Unsupported machine file algorithm".into(),
        ));
    }

    verify_ed25519_signature(
        format!("machine/{}", envelope.enc).as_bytes(),
        &envelope.sig,
        public_key_b64,
        true,
    )?;

    let mut parts = envelope.enc.split('.');
    let Some(ciphertext_part) = parts.next() else {
        return Err(Error::OfflineVerificationFailed(
            "Invalid encrypted machine-file format".into(),
        ));
    };
    let Some(nonce_part) = parts.next() else {
        return Err(Error::OfflineVerificationFailed(
            "Invalid encrypted machine-file format".into(),
        ));
    };
    let Some(tag_part) = parts.next() else {
        return Err(Error::OfflineVerificationFailed(
            "Invalid encrypted machine-file format".into(),
        ));
    };
    if parts.next().is_some() {
        return Err(Error::OfflineVerificationFailed(
            "Invalid encrypted machine-file format".into(),
        ));
    }

    let ciphertext = decode_base64url(ciphertext_part)?;
    let nonce = decode_base64url(nonce_part)?;
    let tag = decode_base64url(tag_part)?;
    if nonce.len() != 12 || tag.len() != 16 {
        return Err(Error::OfflineVerificationFailed(
            "Invalid encrypted machine-file payload".into(),
        ));
    }

    let key = derive_key(license_key, fingerprint);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| Error::Crypto(format!("Invalid AES key: {e}")))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| Error::OfflineVerificationFailed("DECRYPTION_FAILED".into()))?;

    let payload_json: serde_json::Value = serde_json::from_slice(&plaintext)?;
    let payload = parse_machine_file_payload(&payload_json)?;
    let now = chrono::Utc::now().timestamp();

    if payload.nbf > 0 && payload.nbf > now + 300 {
        return Err(Error::OfflineVerificationFailed(
            "TOKEN_NOT_YET_VALID".into(),
        ));
    }
    if payload.exp > 0 && now > payload.exp + payload.grace_period {
        return Err(Error::OfflineVerificationFailed("TOKEN_EXPIRED".into()));
    }
    if let Some(license_expires_at) = payload.license_expires_at {
        if now > license_expires_at {
            return Err(Error::OfflineVerificationFailed("LICENSE_EXPIRED".into()));
        }
    }
    if !payload.fingerprint.is_empty() && !constant_time_equal(&payload.fingerprint, fingerprint) {
        return Err(Error::OfflineVerificationFailed(
            "FINGERPRINT_MISMATCH".into(),
        ));
    }

    Ok(payload)
}

/// Convert a decrypted machine-file payload to a `ValidationResult`.
pub fn machine_file_to_validation_result(payload: &MachineFilePayload) -> ValidationResult {
    let license = payload.license.clone().unwrap_or_else(|| LicenseResponse {
        object: "license".into(),
        key: payload.license_key.clone(),
        status: "active".into(),
        starts_at: None,
        expires_at: payload
            .license_expires_at
            .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0)),
        mode: "hardware_locked".into(),
        plan_key: String::new(),
        seat_limit: None,
        active_seats: 0,
        active_entitlements: Vec::new(),
        metadata: Some(payload.metadata.clone()),
        product: Product {
            slug: String::new(),
            name: String::new(),
        },
    });

    ValidationResult {
        object: "validation_result".into(),
        valid: true,
        code: None,
        message: None,
        warnings: None,
        license,
        activation: None,
        offline: true,
    }
}

fn parse_machine_file_envelope(certificate: &str) -> Result<ParsedMachineFileEnvelope> {
    if certificate.is_empty() {
        return Err(Error::OfflineVerificationFailed(
            "Machine file certificate is empty".into(),
        ));
    }

    let cleaned = certificate
        .replace("-----BEGIN MACHINE FILE-----", "")
        .replace("-----END MACHINE FILE-----", "")
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|_| Error::OfflineVerificationFailed("Invalid machine file encoding".into()))?;
    let envelope: serde_json::Value = serde_json::from_slice(&decoded)?;

    let enc = envelope
        .get("enc")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let sig = envelope
        .get("sig")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let alg = envelope
        .get("alg")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();

    if enc.is_empty() || sig.is_empty() {
        return Err(Error::OfflineVerificationFailed(
            "Machine file envelope is incomplete".into(),
        ));
    }

    Ok(ParsedMachineFileEnvelope { enc, sig, alg })
}

fn parse_machine_file_payload(value: &serde_json::Value) -> Result<MachineFilePayload> {
    let meta = value.get("meta").and_then(|value| value.as_object());
    let data = value.get("data").and_then(|value| value.as_object());
    let attrs = data
        .and_then(|data| data.get("attributes"))
        .and_then(|value| value.as_object());

    let license = value
        .get("included")
        .and_then(|value| value.as_array())
        .and_then(|items| {
            items.iter().find_map(|item| {
                (item.get("type").and_then(|ty| ty.as_str()) == Some("licenses"))
                    .then(|| serde_json::from_value::<LicenseResponse>(item.clone()).ok())
                    .flatten()
            })
        });

    Ok(MachineFilePayload {
        schema_version: meta
            .and_then(|meta| meta.get("schema_version"))
            .and_then(|value| value.as_u64())
            .unwrap_or_default() as u32,
        issued: meta
            .and_then(|meta| meta.get("issued"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        iat: meta
            .and_then(|meta| meta.get("iat"))
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        expiry: meta
            .and_then(|meta| meta.get("expiry"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        exp: meta
            .and_then(|meta| meta.get("exp"))
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        nbf: meta
            .and_then(|meta| meta.get("nbf"))
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        ttl: meta
            .and_then(|meta| meta.get("ttl"))
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        grace_period: meta
            .and_then(|meta| meta.get("grace_period"))
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        license_key: meta
            .and_then(|meta| meta.get("lic"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        license_expires_at: meta
            .and_then(|meta| meta.get("license_exp"))
            .and_then(|value| value.as_i64()),
        key_id: meta
            .and_then(|meta| meta.get("kid"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        sdk_version: meta
            .and_then(|meta| meta.get("sdk_version"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        machine_id: data
            .and_then(|data| data.get("id"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        fingerprint: attrs
            .and_then(|attrs| attrs.get("fingerprint"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        fingerprint_components: attrs
            .and_then(|attrs| attrs.get("fingerprint_components"))
            .and_then(|value| value.as_object())
            .map(|map| {
                map.iter()
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            value
                                .as_str()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| value.to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
        device_name: attrs
            .and_then(|attrs| attrs.get("name"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        platform: attrs
            .and_then(|attrs| attrs.get("platform"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        created_at: attrs
            .and_then(|attrs| attrs.get("created"))
            .and_then(|value| value.as_str())
            .and_then(parse_datetime),
        metadata: attrs
            .and_then(|attrs| attrs.get("metadata"))
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default(),
        license,
    })
}

fn verify_ed25519_signature(
    message: &[u8],
    signature_b64: &str,
    public_key_b64: &str,
    url_safe_no_pad: bool,
) -> Result<bool> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| Error::Crypto(format!("Failed to decode public key: {e}")))?;
    let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice())
        .map_err(|e| Error::Crypto(format!("Invalid public key: {e}")))?;

    let signature_engine = if url_safe_no_pad {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD
    };
    let signature_bytes = signature_engine
        .decode(signature_b64)
        .map_err(|e| Error::Crypto(format!("Failed to decode signature: {e}")))?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| Error::Crypto(format!("Invalid signature: {e}")))?;

    verifying_key
        .verify(message, &signature)
        .map(|_| true)
        .map_err(|e| Error::Crypto(format!("Signature verification failed: {e}")))
}

fn decode_base64url(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| Error::Crypto(format!("Failed to decode base64url payload: {e}")))
}

fn derive_key(license_key: &str, fingerprint: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(license_key.as_bytes());
    hasher.update(fingerprint.as_bytes());
    hasher.finalize().into()
}

fn parse_datetime(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (l, r) in left.as_bytes().iter().zip(right.as_bytes()) {
        diff |= l ^ r;
    }

    diff == 0
}
