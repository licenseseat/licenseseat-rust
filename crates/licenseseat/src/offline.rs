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

const MAX_CANONICAL_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_LIFETIME_SECONDS: i64 = 100 * 366 * 24 * 60 * 60;
const MAX_ENTITLEMENTS: usize = 500;
const MAX_IDENTITY_BYTES: usize = 255;
const MAX_LICENSE_KEY_BYTES: usize = 512;
const MAX_METADATA_BYTES: usize = 128 * 1024;
const MAX_METADATA_ENTRIES: usize = 256;
const MAX_JSON_DEPTH: usize = 20;
const MAX_JSON_NODES: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 64 * 1024;
const MAX_FINGERPRINT_COMPONENTS: usize = 64;
const MAX_COMPONENT_KEY_BYTES: usize = 100;
const MAX_COMPONENT_VALUE_BYTES: usize = 1_024;

const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_ENCRYPTED_TEXT_BYTES: usize = 768 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
const MAX_MACHINE_GRACE_SECONDS: i64 = 30 * 86_400;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    validate_offline_token_structure(token, signing_key)?;
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
pub fn token_to_validation_result(token: &OfflineTokenResponse) -> ValidationResult {
    let payload = &token.token;

    let entitlements: Vec<Entitlement> = payload
        .entitlements
        .iter()
        .filter(|entitlement| {
            entitlement
                .expires_at
                .is_none_or(|expires_at| expires_at > chrono::Utc::now().timestamp())
        })
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

    let envelope = parse_machine_file_envelope(&machine_file.certificate)?;
    if envelope.alg != "aes-256-gcm+ed25519" || !safe_key_id(&envelope.kid) {
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

    if payload.nbf > now.saturating_add(300) {
        return Err(Error::OfflineVerificationFailed(
            "TOKEN_NOT_YET_VALID".into(),
        ));
    }
    if payload
        .exp
        .checked_add(payload.grace_period)
        .is_none_or(|deadline| deadline <= now)
    {
        return Err(Error::OfflineVerificationFailed("TOKEN_EXPIRED".into()));
    }
    if let Some(license_expires_at) = payload.license_expires_at {
        if now >= license_expires_at {
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
    let mut license = payload.license.clone().unwrap_or_else(|| LicenseResponse {
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
            slug: payload.product_slug.clone(),
            name: payload.product_slug.clone(),
        },
    });
    let now = chrono::Utc::now();
    license
        .active_entitlements
        .retain(|entitlement| entitlement.expires_at.is_none_or(|expiry| expiry > now));

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
                || line.len() > 64
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        })
    {
        return Err(Error::OfflineVerificationFailed(
            "Invalid machine file format".into(),
        ));
    }
    let cleaned = lines[1..lines.len() - 1].concat();

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|_| Error::OfflineVerificationFailed("Invalid machine file encoding".into()))?;
    if decoded.len() > MAX_ENCRYPTED_TEXT_BYTES {
        return Err(Error::OfflineVerificationFailed(
            "Invalid machine file format".into(),
        ));
    }
    let envelope: ParsedMachineFileEnvelope = serde_json::from_slice(&decoded)?;

    if envelope.enc.is_empty()
        || envelope.enc.len() > MAX_ENCRYPTED_TEXT_BYTES
        || envelope.sig.is_empty()
        || envelope.sig.len() > 128
        || envelope.alg != "aes-256-gcm+ed25519"
        || !safe_key_id(&envelope.kid)
    {
        return Err(Error::OfflineVerificationFailed(
            "Machine file envelope is incomplete".into(),
        ));
    }

    Ok(envelope)
}

pub(crate) fn machine_file_key_id(certificate: &str) -> Result<String> {
    Ok(parse_machine_file_envelope(certificate)?.kid)
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
                    .then(|| parse_embedded_license(item).ok())
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
        product_slug: data
            .and_then(|data| data.get("relationships"))
            .and_then(serde_json::Value::as_object)
            .and_then(|relationships| relationships.get("product"))
            .and_then(|value| value.get("data"))
            .and_then(serde_json::Value::as_object)
            .and_then(|relationship| relationship.get("id"))
            .and_then(serde_json::Value::as_str)
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

fn valid_relationship_shape(value: Option<&serde_json::Value>, expected_type: &str) -> bool {
    let Some(wrapper) = value.and_then(serde_json::Value::as_object) else {
        return false;
    };
    let Some(data) = wrapper.get("data").and_then(serde_json::Value::as_object) else {
        return false;
    };
    contains_only_keys(wrapper, &["data"])
        && contains_only_keys(data, &["type", "id"])
        && data.get("type").and_then(serde_json::Value::as_str) == Some(expected_type)
        && data.get("id").is_some_and(serde_json::Value::is_string)
}

fn validate_machine_file_payload(
    value: &serde_json::Value,
    envelope_key_id: &str,
    expected_license_key: &str,
    expected_fingerprint: &str,
) -> Result<()> {
    let root = value.as_object().ok_or_else(invalid_machine_payload)?;
    if !contains_only_keys(root, &["meta", "data", "included"]) {
        return Err(invalid_machine_payload());
    }
    let meta = root
        .get("meta")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    let data = root
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    let included = root
        .get("included")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid_machine_payload)?;
    if !contains_only_keys(
        meta,
        &[
            "schema_version",
            "issued",
            "iat",
            "expiry",
            "exp",
            "nbf",
            "ttl",
            "grace_period",
            "lic",
            "license_exp",
            "kid",
            "sdk_version",
        ],
    ) || !contains_only_keys(data, &["type", "id", "attributes", "relationships"])
    {
        return Err(invalid_machine_payload());
    }

    let integer = |name: &str| {
        meta.get(name)
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(invalid_machine_payload)
    };
    let schema_version = meta
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(invalid_machine_payload)?;
    let iat = integer("iat")?;
    let exp = integer("exp")?;
    let nbf = integer("nbf")?;
    let ttl = integer("ttl")?;
    let grace = integer("grace_period")?;
    let license_key = meta
        .get("lic")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    let key_id = meta
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    let issued = meta
        .get("issued")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_datetime)
        .ok_or_else(invalid_machine_payload)?;
    let expiry = meta
        .get("expiry")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_datetime)
        .ok_or_else(invalid_machine_payload)?;

    if schema_version != 2
        || !constant_time_equal(license_key, expected_license_key)
        || !constant_time_equal(key_id, envelope_key_id)
        || !safe_key_id(key_id)
        || iat <= 0
        || ttl <= 0
        || ttl > MAX_TOKEN_LIFETIME_SECONDS
        || !(0..=MAX_MACHINE_GRACE_SECONDS).contains(&grace)
        || iat > nbf
        || nbf > exp
        || exp.checked_sub(iat) != Some(ttl)
        || issued.timestamp() != iat
        || expiry.timestamp() != exp
        || meta
            .get("license_exp")
            .is_some_and(|value| !value.is_null() && value.as_i64().is_none())
        || meta
            .get("license_exp")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|license_exp| license_exp <= iat)
        || meta.get("sdk_version").is_some_and(|value| {
            !value.is_null()
                && value
                    .as_str()
                    .is_none_or(|version| !safe_text(version, 100, 1))
        })
    {
        return Err(invalid_machine_payload());
    }

    if data.get("type").and_then(serde_json::Value::as_str) != Some("machines")
        || data
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|id| !safe_text(id, 255, 1))
    {
        return Err(invalid_machine_payload());
    }
    let attributes = data
        .get("attributes")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    if !contains_only_keys(
        attributes,
        &[
            "fingerprint",
            "fingerprint_components",
            "name",
            "platform",
            "created",
            "metadata",
        ],
    ) || attributes.get("name").is_some_and(|value| {
        !value.is_null()
            && value
                .as_str()
                .is_none_or(|name| !safe_text(name, MAX_IDENTITY_BYTES, 1))
    }) || attributes.get("platform").is_some_and(|value| {
        !value.is_null()
            && value
                .as_str()
                .is_none_or(|platform| !safe_text(platform, 100, 1))
    }) || attributes
        .get("created")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_datetime)
        .is_none()
    {
        return Err(invalid_machine_payload());
    }
    let fingerprint = attributes
        .get("fingerprint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    if !safe_text(fingerprint, MAX_IDENTITY_BYTES, 8)
        || !constant_time_equal(fingerprint, expected_fingerprint)
    {
        return Err(Error::OfflineVerificationFailed(
            "FINGERPRINT_MISMATCH".into(),
        ));
    }

    let relationships = data
        .get("relationships")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    if !contains_only_keys(relationships, &["license", "product"])
        || !valid_relationship_shape(relationships.get("license"), "licenses")
        || !valid_relationship_shape(relationships.get("product"), "products")
    {
        return Err(invalid_machine_payload());
    }
    let relationship_license = relationships
        .get("license")
        .and_then(|value| value.get("data"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    if relationship_license
        .get("type")
        .and_then(serde_json::Value::as_str)
        != Some("licenses")
        || relationship_license
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|key| !constant_time_equal(key, expected_license_key))
    {
        return Err(invalid_machine_payload());
    }

    let relationship_product = relationships
        .get("product")
        .and_then(|value| value.get("data"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    let product_slug = relationship_product
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    if relationship_product
        .get("type")
        .and_then(serde_json::Value::as_str)
        != Some("products")
        || !safe_product_slug(product_slug)
    {
        return Err(invalid_machine_payload());
    }

    match attributes.get("fingerprint_components") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(components))
            if components.len() <= MAX_FINGERPRINT_COMPONENTS
                && components.iter().all(|(key, value)| {
                    safe_text(key, MAX_COMPONENT_KEY_BYTES, 1)
                        && value
                            .as_str()
                            .is_some_and(|value| safe_text(value, MAX_COMPONENT_VALUE_BYTES, 1))
                }) => {}
        _ => return Err(invalid_machine_payload()),
    }
    let metadata = attributes
        .get("metadata")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    if !safe_json_metadata(&serde_json::Value::Object(metadata.clone())) {
        return Err(invalid_machine_payload());
    }

    if included.len() > 1 {
        return Err(invalid_machine_payload());
    }
    if let Some(item) = included.first() {
        let embedded = parse_embedded_license(item)?;
        if !constant_time_equal(&embedded.key, expected_license_key) {
            return Err(invalid_machine_payload());
        }
        if product_slug != embedded.product.slug {
            return Err(invalid_machine_payload());
        }
        let embedded_expiry = embedded.expires_at.map(|expiry| expiry.timestamp());
        let signed_expiry = meta.get("license_exp").and_then(serde_json::Value::as_i64);
        if embedded_expiry != signed_expiry
            || embedded
                .starts_at
                .is_some_and(|starts_at| starts_at.timestamp() > iat)
        {
            return Err(invalid_machine_payload());
        }
    }
    Ok(())
}

fn parse_embedded_license(value: &serde_json::Value) -> Result<LicenseResponse> {
    let object = value.as_object().ok_or_else(invalid_machine_payload)?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    if !contains_only_keys(object, &["type", "id", "attributes"])
        || object.get("type").and_then(serde_json::Value::as_str) != Some("licenses")
        || !safe_text(id, MAX_LICENSE_KEY_BYTES, 1)
    {
        return Err(invalid_machine_payload());
    }
    let attributes = object
        .get("attributes")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid_machine_payload)?;
    if !contains_only_keys(
        attributes,
        &[
            "key",
            "status",
            "mode",
            "seat_limit",
            "plan_key",
            "product_slug",
            "starts_at",
            "ends_at",
            "entitlements",
            "metadata",
        ],
    ) {
        return Err(invalid_machine_payload());
    }
    let key = attributes
        .get("key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    let status = attributes
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    let mode = attributes
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    let plan_key = attributes
        .get("plan_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    let product_slug = attributes
        .get("product_slug")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_machine_payload)?;
    if !constant_time_equal(id, key)
        || status != "active"
        || !matches!(mode, "hardware_locked" | "floating" | "named_user")
        || !safe_text(plan_key, 100, 1)
        || !safe_text(product_slug, 100, 1)
    {
        return Err(invalid_machine_payload());
    }

    let entitlements = attributes
        .get("entitlements")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid_machine_payload)?;
    if entitlements.len() > MAX_ENTITLEMENTS {
        return Err(invalid_machine_payload());
    }
    let mut seen = std::collections::HashSet::new();
    let mut parsed_entitlements = Vec::with_capacity(entitlements.len());
    for entitlement in entitlements {
        let entitlement = entitlement
            .as_object()
            .ok_or_else(invalid_machine_payload)?;
        if !contains_only_keys(entitlement, &["key", "expires_at"]) {
            return Err(invalid_machine_payload());
        }
        let entitlement_key = entitlement
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid_machine_payload)?;
        if !safe_entitlement_key(entitlement_key) || !seen.insert(entitlement_key) {
            return Err(invalid_machine_payload());
        }
        let expires_at = match entitlement.get("expires_at") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(parse_datetime)
                    .ok_or_else(invalid_machine_payload)?,
            ),
        };
        parsed_entitlements.push(Entitlement {
            key: entitlement_key.to_string(),
            expires_at,
            metadata: None,
        });
    }

    let metadata_value = attributes
        .get("metadata")
        .ok_or_else(invalid_machine_payload)?;
    if !metadata_value.is_object() || !safe_json_metadata(metadata_value) {
        return Err(invalid_machine_payload());
    }
    let metadata = serde_json::from_value(metadata_value.clone())?;
    let seat_limit = attributes
        .get("seat_limit")
        .and_then(serde_json::Value::as_u64)
        .map(u32::try_from)
        .transpose()
        .map_err(|_| invalid_machine_payload())?;
    if seat_limit == Some(0) {
        return Err(invalid_machine_payload());
    }

    Ok(LicenseResponse {
        object: "license".into(),
        key: key.to_string(),
        status: status.to_string(),
        starts_at: optional_datetime(attributes.get("starts_at"))?,
        expires_at: optional_datetime(attributes.get("ends_at"))?,
        mode: mode.to_string(),
        plan_key: plan_key.to_string(),
        seat_limit,
        active_seats: 0,
        active_entitlements: parsed_entitlements,
        metadata: Some(metadata),
        product: Product {
            slug: product_slug.to_string(),
            name: product_slug.to_string(),
        },
    })
}

fn safe_product_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (byte == b'-' && index > 0 && index + 1 < value.len())
        })
        && !value.contains("--")
}

fn optional_datetime(
    value: Option<&serde_json::Value>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(parse_datetime)
            .map(Some)
            .ok_or_else(invalid_machine_payload),
    }
}

fn invalid_machine_payload() -> Error {
    Error::OfflineVerificationFailed("Invalid machine-file payload".into())
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

    #[test]
    fn metadata_limits_reject_excessive_depth_and_size() {
        let mut nested = serde_json::Value::Null;
        for _ in 0..=MAX_JSON_DEPTH {
            nested = serde_json::json!({"nested": nested});
        }
        assert!(!safe_json_metadata(&nested));
        assert!(!safe_json_metadata(&serde_json::json!({
            "oversized": "x".repeat(MAX_JSON_STRING_BYTES + 1)
        })));
    }
}
