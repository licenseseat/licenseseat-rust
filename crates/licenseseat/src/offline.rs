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

const MAX_OFFLINE_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

struct ParsedMachineFileEnvelope {
    enc: String,
    sig: String,
    alg: String,
    kid: String,
}

/// Verify an offline token's signature.
pub fn verify_token(
    token: &OfflineTokenResponse,
    signing_key: &SigningKeyResponse,
) -> Result<bool> {
    validate_token_envelope(token)?;
    validate_signing_key(signing_key, &token.token.kid)?;
    verify_ed25519_signature(
        token.canonical.as_bytes(),
        &token.signature.value,
        &signing_key.public_key,
        false,
    )
}

/// Validate every structural and signed-envelope invariant for a legacy token.
pub fn validate_token_envelope(token: &OfflineTokenResponse) -> Result<()> {
    if token.object != "offline_token"
        || token.token.schema_version != 1
        || token.signature.algorithm != "Ed25519"
        || token.signature.key_id.is_empty()
        || token.signature.value.is_empty()
        || token.signature.key_id != token.token.kid
        || token.token.license_key.is_empty()
        || token.token.product_slug.is_empty()
        || token.token.plan_key.is_empty()
        || token.token.mode.is_empty()
        || token.token.kid.is_empty()
        || token.token.device_id.as_deref().is_none_or(str::is_empty)
        || [token.token.iat, token.token.nbf, token.token.exp]
            .into_iter()
            .any(|timestamp| timestamp <= 0 || !is_representable_timestamp(timestamp))
        || token
            .token
            .license_expires_at
            .is_some_and(|timestamp| timestamp <= 0 || !is_representable_timestamp(timestamp))
        || token.token.entitlements.iter().any(|item| {
            item.key.is_empty()
                || item.expires_at.is_some_and(|timestamp| {
                    timestamp <= 0 || !is_representable_timestamp(timestamp)
                })
        })
    {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_TOKEN_CLAIMS".into(),
        ));
    }

    if token.canonical.len() > MAX_OFFLINE_ARTIFACT_BYTES {
        return Err(Error::OfflineVerificationFailed(
            "TOKEN_PAYLOAD_TOO_LARGE".into(),
        ));
    }
    let canonical: serde_json::Value = serde_json::from_str(&token.canonical)
        .map_err(|_| Error::OfflineVerificationFailed("TOKEN_PAYLOAD_MISMATCH".into()))?;
    let decoded = serde_json::to_value(&token.token)?;
    let expected_canonical = serde_json::to_string(&decoded)?;
    if canonical != decoded || token.canonical != expected_canonical {
        return Err(Error::OfflineVerificationFailed(
            "TOKEN_PAYLOAD_MISMATCH".into(),
        ));
    }

    if token.token.iat > token.token.nbf || token.token.nbf >= token.token.exp {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_TIME_WINDOW".into(),
        ));
    }
    Ok(())
}

/// Check a token at an injected time. Kept separate for exact boundary tests.
pub fn check_token_validity_at(
    token: &OfflineTokenResponse,
    now: i64,
    max_clock_skew_seconds: i64,
) -> Result<()> {
    validate_token_envelope(token)?;
    let payload = &token.token;
    let skew = max_clock_skew_seconds.max(0);

    if payload.iat > now.saturating_add(skew) {
        return Err(Error::OfflineVerificationFailed("CLOCK_TAMPER".into()));
    }

    if now.saturating_add(skew) < payload.nbf {
        return Err(Error::OfflineVerificationFailed(
            "Token is not yet valid (nbf)".into(),
        ));
    }

    if now >= payload.exp {
        return Err(Error::OfflineTokenExpired);
    }

    if let Some(license_exp) = payload.license_expires_at {
        if now >= license_exp {
            return Err(Error::OfflineVerificationFailed(
                "License has expired".into(),
            ));
        }
    }

    Ok(())
}

/// Convert an offline token to a `ValidationResult`.
pub fn token_to_validation_result(token: &OfflineTokenResponse) -> Result<ValidationResult> {
    validate_token_envelope(token)?;
    let payload = &token.token;

    let entitlements: Vec<Entitlement> = payload
        .entitlements
        .iter()
        .map(|entitlement| {
            Ok(Entitlement {
                key: entitlement.key.clone(),
                expires_at: entitlement
                    .expires_at
                    .map(timestamp_to_datetime)
                    .transpose()?,
                metadata: None,
            })
        })
        .collect::<Result<_>>()?;

    Ok(ValidationResult {
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
                .map(timestamp_to_datetime)
                .transpose()?,
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
    })
}

pub(crate) fn offline_token_authorization_deadline(
    token: &OfflineTokenResponse,
    max_offline_days: u32,
) -> Result<i64> {
    validate_token_envelope(token)?;
    authorization_deadline(token.token.iat, token.token.exp, 0, max_offline_days)
}

fn validate_offline_token_structure(
    token: &OfflineTokenResponse,
    signing_key: &SigningKeyResponse,
) -> Result<()> {
    let payload = &token.token;
    if token.object != "offline_token"
        || token.signature.algorithm != "Ed25519"
        || signing_key.object != "signing_key"
        || signing_key.algorithm != "Ed25519"
        || signing_key.status != "active"
        || !safe_key_id(&payload.kid)
        || !constant_time_equal(&payload.kid, &token.signature.key_id)
        || !constant_time_equal(&payload.kid, &signing_key.key_id)
        || payload.schema_version != 1
        || !safe_text(&payload.license_key, MAX_LICENSE_KEY_BYTES, 1)
        || !safe_text(&payload.product_slug, MAX_IDENTITY_BYTES, 1)
        || !safe_text(&payload.plan_key, MAX_IDENTITY_BYTES, 1)
        || !matches!(
            payload.mode.as_str(),
            "hardware_locked" | "floating" | "named_user"
        )
        || payload
            .device_id
            .as_deref()
            .is_none_or(|fingerprint| !safe_text(fingerprint, MAX_IDENTITY_BYTES, 8))
        || payload.iat <= 0
        || payload.iat > payload.nbf
        || payload.nbf > payload.exp
        || payload
            .exp
            .checked_sub(payload.iat)
            .is_none_or(|lifetime| lifetime > MAX_TOKEN_LIFETIME_SECONDS)
        || payload
            .license_expires_at
            .is_some_and(|expires_at| expires_at <= payload.iat)
        || payload.seat_limit == Some(0)
        || payload.entitlements.len() > MAX_ENTITLEMENTS
        || payload
            .metadata
            .as_ref()
            .is_some_and(|metadata| !safe_metadata_map(metadata))
        || token.canonical.len() > MAX_CANONICAL_BYTES
        || token.signature.value.len() > 128
    {
        return Err(Error::OfflineVerificationFailed(
            "Invalid offline token structure".into(),
        ));
    }

    let mut entitlement_keys = std::collections::HashSet::new();
    for entitlement in &payload.entitlements {
        if !safe_entitlement_key(&entitlement.key)
            || entitlement
                .expires_at
                .is_some_and(|expires_at| expires_at <= payload.iat)
            || !entitlement_keys.insert(entitlement.key.as_str())
        {
            return Err(Error::OfflineVerificationFailed(
                "Invalid offline token entitlements".into(),
            ));
        }
    }

    let signed_value = crate::strict_json::parse(token.canonical.as_bytes())
        .map_err(|_| Error::OfflineVerificationFailed("Invalid canonical token payload".into()))?;
    let signed_payload: crate::models::OfflineTokenPayload = serde_json::from_value(signed_value)
        .map_err(|_| {
        Error::OfflineVerificationFailed("Invalid canonical token payload".into())
    })?;
    if signed_payload != *payload {
        return Err(Error::OfflineVerificationFailed(
            "Signed payload does not match decoded token claims".into(),
        ));
    }

    Ok(())
}

fn safe_text(value: &str, maximum_bytes: usize, minimum_bytes: usize) -> bool {
    value.len() >= minimum_bytes
        && value.len() <= maximum_bytes
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn safe_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
        })
}

fn safe_entitlement_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        })
}

fn contains_only_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

fn safe_json_metadata(value: &serde_json::Value) -> bool {
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_METADATA_BYTES) {
        return false;
    }

    fn visit(value: &serde_json::Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes = nodes.saturating_add(1);
        if depth > MAX_JSON_DEPTH || *nodes > MAX_JSON_NODES {
            return false;
        }
        match value {
            serde_json::Value::String(value) => value.len() <= MAX_JSON_STRING_BYTES,
            serde_json::Value::Array(values) => {
                values.iter().all(|value| visit(value, depth + 1, nodes))
            }
            serde_json::Value::Object(values) => {
                values.len() <= MAX_METADATA_ENTRIES
                    && values.keys().all(|key| safe_text(key, 255, 1))
                    && values.values().all(|value| visit(value, depth + 1, nodes))
            }
            _ => true,
        }
    }

    visit(value, 0, &mut 0)
}

fn safe_metadata_map(metadata: &std::collections::HashMap<String, serde_json::Value>) -> bool {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return false;
    }
    let value = serde_json::Value::Object(
        metadata
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    safe_json_metadata(&value)
}

/// Verify and decrypt a machine file.
pub fn verify_machine_file(
    machine_file: &MachineFile,
    license_key: &str,
    fingerprint: &str,
    public_key_b64: &str,
    expected_product_slug: Option<&str>,
    max_offline_days: u32,
    max_clock_skew_seconds: i64,
) -> Result<MachineFilePayload> {
    if !safe_text(license_key, MAX_LICENSE_KEY_BYTES, 1) {
        return Err(Error::Configuration("license_key is required".into()));
    }
    if !safe_text(fingerprint, MAX_IDENTITY_BYTES, 8) {
        return Err(Error::Configuration("fingerprint is required".into()));
    }
    if public_key_b64.is_empty() {
        return Err(Error::Configuration("public_key is required".into()));
    }

    if machine_file.algorithm != "aes-256-gcm+ed25519" {
        return Err(Error::OfflineVerificationFailed(
            "Unsupported machine file algorithm".into(),
        ));
    }
    if machine_file.certificate.len() > MAX_OFFLINE_ARTIFACT_BYTES {
        return Err(Error::OfflineVerificationFailed(
            "MACHINE_FILE_TOO_LARGE".into(),
        ));
    }
    if !machine_file.license_key.is_empty()
        && !constant_time_equal(&machine_file.license_key, license_key)
    {
        return Err(Error::OfflineVerificationFailed("LICENSE_MISMATCH".into()));
    }
    if !machine_file.fingerprint.is_empty()
        && !constant_time_equal(&machine_file.fingerprint, fingerprint)
    {
        return Err(Error::OfflineVerificationFailed(
            "FINGERPRINT_MISMATCH".into(),
        ));
    }

    let envelope = parse_machine_file_envelope(&machine_file.certificate)?;
    if envelope.alg != "aes-256-gcm+ed25519" || envelope.kid.is_empty() {
        return Err(Error::OfflineVerificationFailed(
            "Unsupported machine file envelope".into(),
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

    if ciphertext_part.len() > MAX_ENCRYPTED_TEXT_BYTES
        || nonce_part.len() > 32
        || tag_part.len() > 32
    {
        return Err(Error::OfflineVerificationFailed(
            "Invalid encrypted machine-file payload".into(),
        ));
    }
    let ciphertext = decode_base64url(ciphertext_part)?;
    let nonce = decode_base64url(nonce_part)?;
    let tag = decode_base64url(tag_part)?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES || nonce.len() != 12 || tag.len() != 16 {
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
    if plaintext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(Error::OfflineVerificationFailed(
            "Decrypted machine-file payload is too large".into(),
        ));
    }

    let payload_json =
        crate::strict_json::parse(&plaintext).map_err(|_| invalid_machine_payload())?;
    validate_machine_file_payload(&payload_json, &envelope.kid, license_key, fingerprint)?;
    let payload = parse_machine_file_payload(&payload_json)?;
    let now = chrono::Utc::now().timestamp();
    let skew = max_clock_skew_seconds.max(0);
    let issued_timestamp = parse_datetime(&payload.issued).map(|value| value.timestamp());
    let expiry_timestamp = parse_datetime(&payload.expiry).map(|value| value.timestamp());

    if payload.schema_version != 2
        || payload.key_id.is_empty()
        || !constant_time_equal(&payload.key_id, &envelope.kid)
        || payload.license_key.is_empty()
        || !constant_time_equal(&payload.license_key, license_key)
        || payload.machine_id.is_empty()
        || payload.fingerprint.is_empty()
        || !machine_file_time_claims_are_valid(&payload, issued_timestamp, expiry_timestamp)
    {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_MACHINE_FILE_CLAIMS".into(),
        ));
    }
    if let Some(expected_product_slug) = expected_product_slug {
        if payload.product_slug.is_empty()
            || !constant_time_equal(&payload.product_slug, expected_product_slug)
        {
            return Err(Error::OfflineVerificationFailed("PRODUCT_MISMATCH".into()));
        }
    }
    if payload.iat > now.saturating_add(skew) {
        return Err(Error::OfflineVerificationFailed("CLOCK_TAMPER".into()));
    }
    if payload.nbf > now.saturating_add(skew) {
        return Err(Error::OfflineVerificationFailed(
            "TOKEN_NOT_YET_VALID".into(),
        ));
    }
    let effective_expiry = payload
        .exp
        .checked_add(payload.grace_period)
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_TIME_WINDOW".into()))?;
    if now >= effective_expiry {
        return Err(Error::OfflineVerificationFailed("TOKEN_EXPIRED".into()));
    }
    if let Some(license_expires_at) = payload.license_expires_at {
        if now >= license_expires_at {
            return Err(Error::OfflineVerificationFailed("LICENSE_EXPIRED".into()));
        }
    }
    if !constant_time_equal(&payload.fingerprint, fingerprint) {
        return Err(Error::OfflineVerificationFailed(
            "FINGERPRINT_MISMATCH".into(),
        ));
    }
    if max_offline_days > 0 {
        let maximum_age = i64::from(max_offline_days).saturating_mul(86_400);
        let age = now.saturating_sub(payload.iat);
        if age < -skew {
            return Err(Error::OfflineVerificationFailed("CLOCK_TAMPER".into()));
        }
        if age >= maximum_age {
            return Err(Error::OfflineVerificationFailed(
                "GRACE_PERIOD_EXPIRED".into(),
            ));
        }
    }
    if let Some(license) = payload.license.as_ref() {
        if license.object != "license"
            || !constant_time_equal(&license.key, license_key)
            || !license.status.eq_ignore_ascii_case("active")
            || expected_product_slug
                .is_some_and(|slug| !constant_time_equal(&license.product.slug, slug))
            || license
                .starts_at
                .is_some_and(|starts_at| now < starts_at.timestamp())
            || license
                .expires_at
                .is_some_and(|expires_at| now >= expires_at.timestamp())
        {
            return Err(Error::OfflineVerificationFailed(
                "INCLUDED_LICENSE_MISMATCH".into(),
            ));
        }
    }

    Ok(payload)
}

fn machine_file_time_claims_are_valid(
    payload: &MachineFilePayload,
    issued_timestamp: Option<i64>,
    expiry_timestamp: Option<i64>,
) -> bool {
    [payload.iat, payload.nbf, payload.exp]
        .into_iter()
        .all(|timestamp| timestamp > 0 && is_representable_timestamp(timestamp))
        && payload.license_expires_at.is_none_or(|timestamp| {
            timestamp > 0 && is_representable_timestamp(timestamp)
        })
        && payload.ttl > 0
        && (0..=30 * 86_400).contains(&payload.grace_period)
        && payload.iat <= payload.nbf
        // A not-before instant equal to expiry has no valid authorization
        // window. Grace extends an already-valid artifact; it must not turn a
        // zero-width signed window into a grant.
        && payload.nbf < payload.exp
        && payload.exp.checked_sub(payload.iat) == Some(payload.ttl)
        && issued_timestamp == Some(payload.iat)
        && expiry_timestamp == Some(payload.exp)
}

/// Convert a decrypted machine-file payload to a `ValidationResult`.
pub fn machine_file_to_validation_result(payload: &MachineFilePayload) -> Result<ValidationResult> {
    let license = payload.license.clone().map_or_else(
        || -> Result<LicenseResponse> {
            Ok(LicenseResponse {
                object: "license".into(),
                key: payload.license_key.clone(),
                status: "active".into(),
                starts_at: None,
                expires_at: payload
                    .license_expires_at
                    .map(timestamp_to_datetime)
                    .transpose()?,
                mode: "hardware_locked".into(),
                plan_key: String::new(),
                seat_limit: None,
                active_seats: 0,
                active_entitlements: Vec::new(),
                metadata: Some(payload.metadata.clone()),
                product: Product {
                    slug: payload.product_slug.clone(),
                    name: payload.product_slug.clone(),
                },
            })
        },
        Ok,
    )?;

    Ok(ValidationResult {
        object: "validation_result".into(),
        valid: true,
        code: None,
        message: None,
        warnings: None,
        license,
        activation: None,
        offline: true,
    })
}

pub(crate) fn machine_file_authorization_deadline(
    payload: &MachineFilePayload,
    max_offline_days: u32,
) -> Result<i64> {
    authorization_deadline(
        payload.iat,
        payload.exp,
        payload.grace_period,
        max_offline_days,
    )
}

fn parse_machine_file_envelope(certificate: &str) -> Result<ParsedMachineFileEnvelope> {
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::OfflineVerificationFailed(
            "Machine file certificate is empty".into(),
        ));
    }

    let lines = certificate
        .trim()
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>();
    if lines.len() < 3
        || lines.first() != Some(&"-----BEGIN MACHINE FILE-----")
        || lines.last() != Some(&"-----END MACHINE FILE-----")
        || lines[1..lines.len() - 1].iter().any(|line| {
            line.is_empty()
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        })
    {
        return Err(Error::OfflineVerificationFailed(
            "Invalid machine file format".into(),
        ));
    }
    let cleaned = lines[1..lines.len() - 1].join("");

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|_| Error::OfflineVerificationFailed("Invalid machine file encoding".into()))?;
    if decoded.len() > MAX_ENCRYPTED_TEXT_BYTES {
        return Err(Error::OfflineVerificationFailed(
            "Invalid machine file format".into(),
        ));
    }
    let envelope: ParsedMachineFileEnvelope = serde_json::from_slice(&decoded)?;

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
    let kid = envelope
        .get("kid")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();

    if enc.is_empty() || sig.is_empty() || alg.is_empty() || kid.is_empty() {
        return Err(Error::OfflineVerificationFailed(
            "Machine file envelope is incomplete".into(),
        ));
    }

    Ok(ParsedMachineFileEnvelope { enc, sig, alg, kid })
}

pub(crate) fn machine_file_key_id(certificate: &str) -> Result<String> {
    Ok(parse_machine_file_envelope(certificate)?.kid)
}

fn parse_machine_file_payload(value: &serde_json::Value) -> Result<MachineFilePayload> {
    let root = value
        .as_object()
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_MACHINE_FILE_PAYLOAD".into()))?;
    let meta = root
        .get("meta")
        .and_then(|value| value.as_object())
        .ok_or_else(|| Error::OfflineVerificationFailed("MISSING_MACHINE_FILE_METADATA".into()))?;
    let data = root
        .get("data")
        .and_then(|value| value.as_object())
        .ok_or_else(|| Error::OfflineVerificationFailed("MISSING_MACHINE_DATA".into()))?;
    if data.get("type").and_then(|value| value.as_str()) != Some("machines") {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_MACHINE_DATA".into(),
        ));
    }
    let attrs = data.get("attributes").and_then(|value| value.as_object());
    let attrs = attrs
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_MACHINE_ATTRIBUTES".into()))?;
    let relationships = data
        .get("relationships")
        .and_then(|value| value.as_object());
    let relationships = relationships
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_MACHINE_RELATIONSHIPS".into()))?;
    let relationship_id = |name: &str, expected_type: &str| -> Result<String> {
        let relationship = relationships
            .get(name)
            .and_then(|value| value.get("data"))
            .and_then(|value| value.as_object())
            .ok_or_else(|| {
                Error::OfflineVerificationFailed("INVALID_MACHINE_RELATIONSHIPS".into())
            })?;
        if relationship.get("type").and_then(|value| value.as_str()) != Some(expected_type) {
            return Err(Error::OfflineVerificationFailed(
                "INVALID_MACHINE_RELATIONSHIPS".into(),
            ));
        }
        let id = relationship
            .get("id")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::OfflineVerificationFailed("INVALID_MACHINE_RELATIONSHIPS".into())
            })?;
        Ok(id.to_string())
    };
    let relationship_license_key = relationship_id("license", "licenses")?;
    let product_slug = relationship_id("product", "products")?;

    let included = match root.get("included") {
        Some(serde_json::Value::Array(items)) => items.as_slice(),
        None => &[],
        Some(_) => {
            return Err(Error::OfflineVerificationFailed(
                "INVALID_INCLUDED_LICENSE".into(),
            ));
        }
    };
    let included_licenses = included
        .iter()
        .filter(|item| item.get("type").and_then(|ty| ty.as_str()) == Some("licenses"))
        .collect::<Vec<_>>();
    if included_licenses.len() > 1 {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_INCLUDED_LICENSE".into(),
        ));
    }
    let license = included_licenses
        .first()
        .map(|item| parse_included_license(item, &product_slug))
        .transpose()?;

    let license_key = meta
        .get("lic")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    if !constant_time_equal(&relationship_license_key, &license_key) {
        return Err(Error::OfflineVerificationFailed(
            "MACHINE_RELATIONSHIP_MISMATCH".into(),
        ));
    }

    let schema_version = meta
        .get("schema_version")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_default();
    let license_expires_at =
        match meta.get("license_exp") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(value.as_i64().ok_or_else(|| {
                Error::OfflineVerificationFailed("INVALID_LICENSE_EXPIRY".into())
            })?),
        };

    Ok(MachineFilePayload {
        schema_version,
        issued: meta
            .get("issued")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        iat: meta
            .get("iat")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        expiry: meta
            .get("expiry")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        exp: meta
            .get("exp")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        nbf: meta
            .get("nbf")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        ttl: meta
            .get("ttl")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        grace_period: meta
            .get("grace_period")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        license_key,
        product_slug,
        license_expires_at,
        key_id: meta
            .get("kid")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        sdk_version: meta
            .get("sdk_version")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        machine_id: data
            .get("id")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        fingerprint: attrs
            .get("fingerprint")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        fingerprint_components: attrs
            .get("fingerprint_components")
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
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        platform: attrs
            .get("platform")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        created_at: optional_datetime(attrs.get("created"), "machine creation")?,
        metadata: attrs
            .get("metadata")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default(),
        license,
    })
}

fn parse_included_license(
    value: &serde_json::Value,
    relationship_product: &str,
) -> Result<LicenseResponse> {
    let id = value
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let attributes = value
        .get("attributes")
        .and_then(|value| value.as_object())
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_INCLUDED_LICENSE".into()))?;
    let string = |key: &str| {
        attributes
            .get(key)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let key = {
        let attribute_key = string("key");
        if attribute_key.is_empty() {
            id.to_string()
        } else {
            attribute_key
        }
    };
    if id.is_empty() || key.is_empty() || !constant_time_equal(id, &key) {
        return Err(Error::OfflineVerificationFailed(
            "INCLUDED_LICENSE_MISMATCH".into(),
        ));
    }

    let product_slug = {
        let attribute_product = string("product_slug");
        if attribute_product.is_empty() {
            relationship_product.to_string()
        } else {
            attribute_product
        }
    };
    if !relationship_product.is_empty()
        && !product_slug.is_empty()
        && !constant_time_equal(relationship_product, &product_slug)
    {
        return Err(Error::OfflineVerificationFailed(
            "INCLUDED_PRODUCT_MISMATCH".into(),
        ));
    }
    if product_slug.is_empty()
        || string("status").is_empty()
        || string("mode").is_empty()
        || string("plan_key").is_empty()
    {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_INCLUDED_LICENSE".into(),
        ));
    }

    let seat_limit = match attributes.get("seat_limit") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| {
                    Error::OfflineVerificationFailed("INVALID_INCLUDED_LICENSE".into())
                })?,
        ),
    };

    let entitlement_items = match attributes.get("entitlements") {
        Some(serde_json::Value::Array(items)) => items.as_slice(),
        None => &[],
        Some(_) => {
            return Err(Error::OfflineVerificationFailed(
                "INVALID_INCLUDED_ENTITLEMENT".into(),
            ));
        }
    };
    let active_entitlements = entitlement_items
        .iter()
        .map(|item| {
            let key = item
                .get("key")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            if key.is_empty() {
                return Err(Error::OfflineVerificationFailed(
                    "INVALID_INCLUDED_ENTITLEMENT".into(),
                ));
            }
            let expires_at = optional_datetime(item.get("expires_at"), "entitlement expiry")?;
            Ok(Entitlement {
                key,
                expires_at,
                metadata: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let metadata = attributes
        .get("metadata")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;

    Ok(LicenseResponse {
        object: "license".into(),
        key,
        status: string("status"),
        starts_at: optional_datetime(attributes.get("starts_at"), "license start")?,
        expires_at: optional_datetime(attributes.get("ends_at"), "license expiry")?,
        mode: string("mode"),
        plan_key: string("plan_key"),
        seat_limit,
        active_seats: 0,
        active_entitlements,
        metadata,
        product: Product {
            slug: product_slug.clone(),
            name: product_slug,
        },
    })
}

fn optional_datetime(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => {
            parse_datetime(value).map(Some).ok_or_else(|| {
                Error::OfflineVerificationFailed(format!(
                    "INVALID_{}",
                    field.replace(' ', "_").to_ascii_uppercase()
                ))
            })
        }
        Some(_) => Err(Error::OfflineVerificationFailed(format!(
            "INVALID_{}",
            field.replace(' ', "_").to_ascii_uppercase()
        ))),
    }
}

fn timestamp_to_datetime(timestamp: i64) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_TIMESTAMP".into()))
}

fn is_representable_timestamp(timestamp: i64) -> bool {
    chrono::DateTime::from_timestamp(timestamp, 0).is_some()
}

fn authorization_deadline(
    issued_at: i64,
    expires_at: i64,
    grace_period: i64,
    max_offline_days: u32,
) -> Result<i64> {
    let artifact_deadline = expires_at
        .checked_add(grace_period)
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_TIME_WINDOW".into()))?;
    if max_offline_days == 0 {
        return Ok(artifact_deadline);
    }

    let maximum_age = i64::from(max_offline_days)
        .checked_mul(86_400)
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_TIME_WINDOW".into()))?;
    let host_deadline = issued_at
        .checked_add(maximum_age)
        .ok_or_else(|| Error::OfflineVerificationFailed("INVALID_TIME_WINDOW".into()))?;
    Ok(artifact_deadline.min(host_deadline))
}

/// Validate a signing-key response before it becomes a trust anchor.
pub fn validate_signing_key(signing_key: &SigningKeyResponse, expected_key_id: &str) -> Result<()> {
    if expected_key_id.is_empty()
        || signing_key.object != "signing_key"
        || !constant_time_equal(&signing_key.key_id, expected_key_id)
        || signing_key.algorithm != "Ed25519"
        || signing_key.status != "active"
    {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_SIGNING_KEY_METADATA".into(),
        ));
    }

    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&signing_key.public_key)
        .map_err(|_| Error::OfflineVerificationFailed("INVALID_SIGNING_KEY".into()))?;
    if public_key.len() != 32 {
        return Err(Error::OfflineVerificationFailed(
            "INVALID_SIGNING_KEY".into(),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{OfflineEntitlement, OfflineTokenPayload, OfflineTokenSignature};

    fn token_with_entitlement_expiry(expires_at: Option<i64>) -> OfflineTokenResponse {
        let payload = OfflineTokenPayload {
            schema_version: 1,
            license_key: "TEST-LICENSE".into(),
            product_slug: "test-product".into(),
            plan_key: "pro".into(),
            mode: "hardware_locked".into(),
            seat_limit: Some(1),
            device_id: Some("test-installation".into()),
            iat: 1_700_000_000,
            exp: 1_700_864_000,
            nbf: 1_700_000_000,
            license_expires_at: Some(1_700_864_000),
            kid: "key-1".into(),
            entitlements: vec![OfflineEntitlement {
                key: "pro-feature".into(),
                expires_at,
            }],
            metadata: None,
        };
        OfflineTokenResponse {
            object: "offline_token".into(),
            canonical: serde_json::to_string(&payload).unwrap(),
            token: payload,
            signature: OfflineTokenSignature {
                algorithm: "Ed25519".into(),
                key_id: "key-1".into(),
                value: "signature".into(),
            },
        }
    }

    #[test]
    fn unrepresentable_entitlement_expiry_cannot_become_perpetual() {
        let token = token_with_entitlement_expiry(Some(i64::MAX));

        assert!(matches!(
            validate_token_envelope(&token),
            Err(Error::OfflineVerificationFailed(code)) if code == "INVALID_TOKEN_CLAIMS"
        ));
        assert!(token_to_validation_result(&token).is_err());
    }

    #[test]
    fn authorization_deadline_uses_earliest_signed_or_host_limit() {
        let issued_at = 1_700_000_000;
        let signed_expiry = issued_at + 10 * 86_400;

        assert_eq!(
            authorization_deadline(issued_at, signed_expiry, 3_600, 0).unwrap(),
            signed_expiry + 3_600
        );
        assert_eq!(
            authorization_deadline(issued_at, signed_expiry, 3_600, 2).unwrap(),
            issued_at + 2 * 86_400
        );
        assert!(authorization_deadline(i64::MAX, i64::MAX, 1, 0).is_err());
    }

    #[test]
    fn machine_file_claim_window_rejects_non_positive_or_unrepresentable_time() {
        let mut payload = MachineFilePayload {
            schema_version: 2,
            issued: "2026-01-01T00:00:00Z".into(),
            iat: 1_767_225_600,
            expiry: "2026-01-02T00:00:00Z".into(),
            exp: 1_767_312_000,
            nbf: 1_767_225_600,
            ttl: 86_400,
            grace_period: 0,
            license_key: "TEST-LICENSE".into(),
            product_slug: "test-product".into(),
            license_expires_at: None,
            key_id: "key-1".into(),
            sdk_version: None,
            machine_id: "machine-1".into(),
            fingerprint: "test-installation".into(),
            fingerprint_components: Default::default(),
            device_name: "Test Device".into(),
            platform: "test".into(),
            created_at: None,
            metadata: Default::default(),
            license: None,
        };

        assert!(machine_file_time_claims_are_valid(
            &payload,
            Some(payload.iat),
            Some(payload.exp),
        ));

        payload.nbf = 0;
        assert!(!machine_file_time_claims_are_valid(
            &payload,
            Some(payload.iat),
            Some(payload.exp),
        ));
        payload.nbf = payload.iat;
        payload.license_expires_at = Some(i64::MAX);
        assert!(!machine_file_time_claims_are_valid(
            &payload,
            Some(payload.iat),
            Some(payload.exp),
        ));
    }
}
