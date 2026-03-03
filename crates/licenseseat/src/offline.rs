//! Offline validation using Ed25519 cryptographic signatures.
//!
//! This module provides offline license validation when network access
//! is unavailable. It verifies cached offline tokens using Ed25519 signatures.

use crate::error::{Error, Result};
use crate::models::{OfflineTokenResponse, SigningKeyResponse, ValidationResult};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify an offline token's signature.
pub fn verify_token(
    token: &OfflineTokenResponse,
    signing_key: &SigningKeyResponse,
) -> Result<bool> {
    // Decode the public key (API returns standard Base64)
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signing_key.public_key)
        .map_err(|e| Error::Crypto(format!("Failed to decode public key: {}", e)))?;

    let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice())
        .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;

    // Decode the signature (API returns standard Base64)
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.signature.value)
        .map_err(|e| Error::Crypto(format!("Failed to decode signature: {}", e)))?;

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| Error::Crypto(format!("Invalid signature: {}", e)))?;

    // Verify the signature against the canonical JSON
    let message = token.canonical.as_bytes();

    verifying_key
        .verify(message, &signature)
        .map(|_| true)
        .map_err(|e| Error::Crypto(format!("Signature verification failed: {}", e)))
}

/// Check if an offline token is currently valid (not expired, not before).
pub fn check_token_validity(token: &OfflineTokenResponse) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let payload = &token.token;

    // Check not-before
    if now < payload.nbf {
        return Err(Error::OfflineVerificationFailed(
            "Token is not yet valid (nbf)".into(),
        ));
    }

    // Check expiration
    if now > payload.exp {
        return Err(Error::OfflineTokenExpired);
    }

    // Check license expiration
    if let Some(license_exp) = payload.license_expires_at {
        if now > license_exp {
            return Err(Error::OfflineVerificationFailed(
                "License has expired".into(),
            ));
        }
    }

    Ok(())
}

/// Convert an offline token to a ValidationResult for consistent API.
pub fn token_to_validation_result(token: &OfflineTokenResponse) -> ValidationResult {
    use crate::models::*;

    let payload = &token.token;

    // Convert offline entitlements to regular entitlements
    let entitlements: Vec<Entitlement> = payload
        .entitlements
        .iter()
        .map(|e| Entitlement {
            key: e.key.clone(),
            expires_at: e
                .expires_at
                .map(|ts| chrono::DateTime::from_timestamp(ts, 0).unwrap_or_else(chrono::Utc::now)),
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
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
            mode: payload.mode.clone(),
            plan_key: payload.plan_key.clone(),
            seat_limit: payload.seat_limit,
            active_seats: 0, // Not available offline
            active_entitlements: entitlements,
            metadata: payload.metadata.clone(),
            product: Product {
                slug: payload.product_slug.clone(),
                name: payload.product_slug.clone(), // Name not in token
            },
        },
        activation: None,
    }
}
