//! Cryptographic tests - Ed25519 verification, Base64/Base64URL encoding.
//!
//! These tests include RFC 8032 test vectors and mirror the comprehensive
//! crypto tests from C++ and C# SDKs.

use base64::Engine;

// ============================================================================
// Base64 Standard Encoding Tests
// ============================================================================

#[test]
fn test_base64_standard_encode() {
    let cases = vec![
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    for (input, expected) in cases {
        let encoded = base64::engine::general_purpose::STANDARD.encode(input);
        assert_eq!(encoded, expected, "Failed for input: {}", input);
    }
}

#[test]
fn test_base64_standard_decode() {
    let cases = vec![
        ("", ""),
        ("Zg==", "f"),
        ("Zm8=", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYg==", "foob"),
        ("Zm9vYmE=", "fooba"),
        ("Zm9vYmFy", "foobar"),
    ];

    for (input, expected) in cases {
        let decoded = base64::engine::general_purpose::STANDARD.decode(input).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), expected, "Failed for input: {}", input);
    }
}

#[test]
fn test_base64_binary_data() {
    // Test with binary data (all byte values)
    let binary_data: Vec<u8> = (0u8..=255).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&binary_data);
    let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
    assert_eq!(decoded, binary_data);
}

#[test]
fn test_base64_invalid_input() {
    // Invalid characters
    let result = base64::engine::general_purpose::STANDARD.decode("!!!invalid!!!");
    assert!(result.is_err());

    // Invalid length
    let result = base64::engine::general_purpose::STANDARD.decode("abc");
    assert!(result.is_err());
}

// ============================================================================
// Base64URL Encoding Tests (No Padding)
// ============================================================================

#[test]
fn test_base64url_encode() {
    let cases = vec![
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ];

    for (input, expected) in cases {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input);
        assert_eq!(encoded, expected, "Failed for input: {}", input);
    }
}

#[test]
fn test_base64url_decode() {
    let cases = vec![
        ("", ""),
        ("Zg", "f"),
        ("Zm8", "fo"),
        ("Zm9v", "foo"),
        ("Zm9vYg", "foob"),
        ("Zm9vYmE", "fooba"),
        ("Zm9vYmFy", "foobar"),
    ];

    for (input, expected) in cases {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), expected, "Failed for input: {}", input);
    }
}

#[test]
fn test_base64url_special_characters() {
    // URL-safe Base64 uses - and _ instead of + and /
    // Standard: "abc+/def" would encode with + and /
    // URL-safe should encode with - and _

    // Test data that produces + and / in standard Base64
    let data = vec![0xfb, 0xef, 0xbe]; // Produces ++++ in standard
    let standard = base64::engine::general_purpose::STANDARD.encode(&data);
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data);

    // Standard might have + or /
    // URL safe should only have - or _ or alphanumeric
    assert!(url_safe.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
}

#[test]
fn test_base64url_no_padding() {
    // URL-safe encoding without padding should not have = characters
    let data = "test";
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    assert!(!encoded.contains('='));
}

// ============================================================================
// Ed25519 Test Vectors (RFC 8032)
// ============================================================================

#[cfg(feature = "offline")]
mod ed25519_tests {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    // Simple hex decode for test vectors (returns Vec directly)
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8032 Test Vector 1: Empty message
    #[test]
    fn test_ed25519_rfc8032_test1() {
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let message = b"";
        let expected_sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let secret_key_bytes = hex_decode(secret_key_hex);
        let public_key_bytes = hex_decode(public_key_hex);

        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice()).unwrap();

        // Sign and verify
        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());

        // Verify expected signature
        let expected_sig_bytes = hex_decode(expected_sig_hex);
        let expected_sig = Signature::try_from(expected_sig_bytes.as_slice()).unwrap();
        assert_eq!(signature, expected_sig);
    }

    // RFC 8032 Test Vector 2: 1-byte message
    #[test]
    fn test_ed25519_rfc8032_test2() {
        let secret_key_hex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        let public_key_hex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let message = [0x72u8]; // Single byte: 0x72
        let expected_sig_hex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

        let secret_key_bytes = hex_decode(secret_key_hex);
        let public_key_bytes = hex_decode(public_key_hex);

        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice()).unwrap();

        let signature = signing_key.sign(&message);
        assert!(verifying_key.verify(&message, &signature).is_ok());

        let expected_sig_bytes = hex_decode(expected_sig_hex);
        let expected_sig = Signature::try_from(expected_sig_bytes.as_slice()).unwrap();
        assert_eq!(signature, expected_sig);
    }

    // RFC 8032 Test Vector 3: 2-byte message
    #[test]
    fn test_ed25519_rfc8032_test3() {
        let secret_key_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
        let public_key_hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
        let message = [0xaf, 0x82];
        let expected_sig_hex = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

        let secret_key_bytes = hex_decode(secret_key_hex);
        let public_key_bytes = hex_decode(public_key_hex);

        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice()).unwrap();

        let signature = signing_key.sign(&message);
        assert!(verifying_key.verify(&message, &signature).is_ok());

        let expected_sig_bytes = hex_decode(expected_sig_hex);
        let expected_sig = Signature::try_from(expected_sig_bytes.as_slice()).unwrap();
        assert_eq!(signature, expected_sig);
    }

    // Test signature verification with wrong message
    #[test]
    fn test_ed25519_wrong_message() {
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

        let secret_key_bytes = hex_decode(secret_key_hex);
        let public_key_bytes = hex_decode(public_key_hex);

        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice()).unwrap();

        let message = b"correct message";
        let wrong_message = b"wrong message";

        let signature = signing_key.sign(message);

        // Should verify with correct message
        assert!(verifying_key.verify(message, &signature).is_ok());

        // Should fail with wrong message
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    // Test signature verification with wrong public key
    #[test]
    fn test_ed25519_wrong_public_key() {
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        // Different public key
        let wrong_public_key_hex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

        let secret_key_bytes = hex_decode(secret_key_hex);
        let wrong_public_key_bytes = hex_decode(wrong_public_key_hex);

        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let wrong_verifying_key = VerifyingKey::try_from(wrong_public_key_bytes.as_slice()).unwrap();

        let message = b"test message";
        let signature = signing_key.sign(message);

        // Should fail with wrong public key
        assert!(wrong_verifying_key.verify(message, &signature).is_err());
    }

    // Test invalid signature format
    #[test]
    fn test_ed25519_invalid_signature() {
        let public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let public_key_bytes = hex_decode(public_key_hex);
        let verifying_key = VerifyingKey::try_from(public_key_bytes.as_slice()).unwrap();

        let message = b"test message";

        // Invalid signature (wrong length)
        let invalid_sig = [0u8; 32]; // Should be 64 bytes
        let sig_result = Signature::try_from(invalid_sig.as_slice());
        assert!(sig_result.is_err());

        // Invalid signature (correct length but random bytes)
        let invalid_sig = [0u8; 64];
        let sig = Signature::try_from(invalid_sig.as_slice()).unwrap();
        assert!(verifying_key.verify(message, &sig).is_err());
    }

    // Test invalid public key format
    #[test]
    fn test_ed25519_invalid_public_key() {
        // Wrong length
        let invalid_key = [0u8; 16];
        let result = VerifyingKey::try_from(invalid_key.as_slice());
        assert!(result.is_err());

        // Wrong length (too long)
        let invalid_key = [0u8; 64];
        let result = VerifyingKey::try_from(invalid_key.as_slice());
        assert!(result.is_err());
    }
}

// ============================================================================
// Signature Verification Integration Tests
// ============================================================================

// Note: Full integration tests with key generation require the rand crate.
// These tests verify signature concepts through static test vectors instead.

#[cfg(feature = "offline")]
mod signature_integration_tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    // Helper to decode hex
    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_offline_token_signature_flow() {
        // Use a known test vector instead of random key generation
        // RFC 8032 Test Vector 1 secret key
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let secret_key_bytes = hex_to_bytes(secret_key_hex);
        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let public_key = signing_key.verifying_key();

        // Create a canonical JSON payload (simplified)
        let canonical_json = r#"{"exp":1735776000,"iat":1735689600,"license_key":"TEST-KEY","nbf":1735689600,"product_slug":"test"}"#;

        // Sign the canonical JSON
        let signature = signing_key.sign(canonical_json.as_bytes());

        // Encode for transport
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

        // Now simulate verification (what the SDK does)
        let decoded_public_key = base64::engine::general_purpose::STANDARD
            .decode(&public_key_b64)
            .unwrap();
        let decoded_signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&signature_b64)
            .unwrap();

        let verifying_key = VerifyingKey::try_from(decoded_public_key.as_slice()).unwrap();
        let sig = Signature::try_from(decoded_signature.as_slice()).unwrap();

        // Verify
        assert!(verifying_key.verify(canonical_json.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn test_tampered_canonical_json() {
        // Use RFC 8032 Test Vector 1 key
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let secret_key_bytes = hex_to_bytes(secret_key_hex);
        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let public_key = signing_key.verifying_key();

        let canonical_json = r#"{"license_key":"ORIGINAL-KEY"}"#;
        let tampered_json = r#"{"license_key":"TAMPERED-KEY"}"#;

        let signature = signing_key.sign(canonical_json.as_bytes());

        // Verification with original should succeed
        assert!(public_key.verify(canonical_json.as_bytes(), &signature).is_ok());

        // Verification with tampered should fail
        assert!(public_key.verify(tampered_json.as_bytes(), &signature).is_err());
    }

    #[test]
    fn test_standard_base64_signature_verification() {
        // This test verifies the SDK can handle STANDARD base64 encoding
        // (with + and / characters, with = padding) as returned by the LicenseSeat API

        // RFC 8032 Test Vector 1 key
        let secret_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let secret_key_bytes = hex_to_bytes(secret_key_hex);
        let signing_key = SigningKey::try_from(secret_key_bytes.as_slice()).unwrap();
        let public_key = signing_key.verifying_key();

        // Create a canonical JSON payload
        let canonical_json = r#"{"device_id":"test-device-123","license_key":"TEST-KEY","product_slug":"my-product"}"#;

        // Sign the canonical JSON
        let signature = signing_key.sign(canonical_json.as_bytes());

        // Encode using STANDARD base64 (what our API returns)
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        // Verify the encoding looks like standard base64 (may have + or /)
        assert!(public_key_b64.ends_with('=') || public_key_b64.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/'));

        // Decode using STANDARD base64 (matching what the SDK's verify_token does)
        let decoded_public_key = base64::engine::general_purpose::STANDARD
            .decode(&public_key_b64)
            .unwrap();
        let decoded_signature = base64::engine::general_purpose::STANDARD
            .decode(&signature_b64)
            .unwrap();

        let verifying_key = VerifyingKey::try_from(decoded_public_key.as_slice()).unwrap();
        let sig = Signature::try_from(decoded_signature.as_slice()).unwrap();

        // Verify the signature
        assert!(verifying_key.verify(canonical_json.as_bytes(), &sig).is_ok());
    }
}

// ============================================================================
// Utility Function Tests
// ============================================================================

#[test]
fn test_constant_time_comparison() {
    // Simulate constant-time comparison (important for security)
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    // Equal values
    assert!(constant_time_eq(b"hello", b"hello"));
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));

    // Unequal values
    assert!(!constant_time_eq(b"hello", b"world"));
    assert!(!constant_time_eq(b"hello", b"hell"));
    assert!(!constant_time_eq(b"hello", b"helloo"));

    // Single bit difference
    assert!(!constant_time_eq(&[0b00000000], &[0b00000001]));
}

#[test]
fn test_hash_code_deterministic() {
    // Simple hash function should be deterministic
    fn hash_code(s: &str) -> u32 {
        let mut h: u32 = 0;
        for c in s.chars() {
            h = h.wrapping_mul(31).wrapping_add(c as u32);
        }
        h
    }

    let hash1 = hash_code("test string");
    let hash2 = hash_code("test string");
    assert_eq!(hash1, hash2);

    // Different strings should (likely) have different hashes
    let hash3 = hash_code("different string");
    assert_ne!(hash1, hash3);
}

// ============================================================================
// Hex Encoding Tests (for test vector handling)
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn test_hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("Odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex"))
        .collect()
}

#[test]
fn test_hex_encode_decode() {
    let test_cases = vec![
        (vec![0x00], "00"),
        (vec![0xff], "ff"),
        (vec![0xde, 0xad, 0xbe, 0xef], "deadbeef"),
        ((0u8..16).collect::<Vec<_>>(), "000102030405060708090a0b0c0d0e0f"),
    ];

    for (bytes, expected_hex) in test_cases {
        // Encode
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, expected_hex);

        // Decode
        let decoded = test_hex_decode(expected_hex).unwrap();
        assert_eq!(decoded, bytes);
    }
}

#[test]
fn test_hex_invalid_input() {
    // Invalid hex characters
    assert!(test_hex_decode("xyz").is_err());
    assert!(test_hex_decode("gg").is_err());

    // Odd length
    assert!(test_hex_decode("abc").is_err());
}
