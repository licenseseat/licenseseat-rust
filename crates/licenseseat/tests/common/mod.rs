#![allow(dead_code)]

use serde_json::{Value, json};
use wiremock::{Request, Respond, ResponseTemplate};

#[derive(Debug, Clone)]
pub struct ActivationResponder {
    entitlements: Vec<Value>,
}

impl Respond for ActivationResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let segments = request
            .url
            .path_segments()
            .map(|segments| segments.collect::<Vec<_>>())
            .unwrap_or_default();
        let segment_after = |needle: &str| {
            segments
                .iter()
                .position(|segment| *segment == needle)
                .and_then(|index| segments.get(index + 1))
                .copied()
                .unwrap_or_default()
        };
        let product_slug = segment_after("products");
        let request_body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let license_key = request_body
            .get("license_key")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let fingerprint = request_body
            .get("fingerprint")
            .or_else(|| request_body.get("device_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();

        ResponseTemplate::new(201).set_body_json(json!({
            "object": "activation",
            "id": "act-12345-uuid",
            "device_id": fingerprint,
            "device_name": "Test Device",
            "license_key": license_key,
            "activated_at": "2025-01-01T00:00:00Z",
            "deactivated_at": null,
            "ip_address": "127.0.0.1",
            "metadata": null,
            "license": {
                "object": "license",
                "key": license_key,
                "status": "active",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 5,
                "active_seats": 1,
                "active_entitlements": self.entitlements,
                "metadata": null,
                "product": {
                    "slug": product_slug,
                    "name": "Test App"
                }
            }
        }))
    }
}

pub fn activation_responder() -> ActivationResponder {
    ActivationResponder {
        entitlements: Vec::new(),
    }
}

pub fn activation_responder_with_entitlements(entitlements: Vec<Value>) -> ActivationResponder {
    ActivationResponder { entitlements }
}

fn request_identity(request: &Request) -> (String, String) {
    let segments = request
        .url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let segment_after = |needle: &str| {
        segments
            .iter()
            .position(|segment| *segment == needle)
            .and_then(|index| segments.get(index + 1))
            .copied()
            .unwrap_or_default()
    };
    let request_body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
    let license_key = request_body
        .get("license_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    (
        segment_after("products").to_string(),
        license_key.to_string(),
    )
}

#[derive(Debug, Clone)]
pub struct ValidationResponder {
    valid: bool,
    entitlements: Vec<Value>,
}

impl Respond for ValidationResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let (product_slug, license_key) = request_identity(request);
        let request_body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let fingerprint = request_body
            .get("fingerprint")
            .or_else(|| request_body.get("device_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (status, code, message) = if self.valid {
            ("active", Value::Null, Value::Null)
        } else {
            (
                "suspended",
                json!("license_invalid"),
                json!("License is invalid"),
            )
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "object": "validation_result",
            "valid": self.valid,
            "code": code,
            "message": message,
            "warnings": null,
            "license": {
                "object": "license",
                "key": license_key,
                "status": status,
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 5,
                "active_seats": 1,
                "active_entitlements": self.entitlements,
                "metadata": null,
                "product": { "slug": product_slug, "name": "Test App" }
            },
            "activation": self.valid.then(|| json!({
                "object": "activation",
                "id": "act-12345-uuid",
                "device_id": fingerprint,
                "device_name": "Test Device",
                "license_key": license_key,
                "activated_at": "2025-01-01T00:00:00Z",
                "deactivated_at": null,
                "ip_address": "127.0.0.1",
                "metadata": null
            }))
        }))
    }
}

pub fn validation_responder() -> ValidationResponder {
    ValidationResponder {
        valid: true,
        entitlements: Vec::new(),
    }
}

pub fn validation_responder_with_entitlements(entitlements: Vec<Value>) -> ValidationResponder {
    ValidationResponder {
        valid: true,
        entitlements,
    }
}

pub fn invalid_validation_responder() -> ValidationResponder {
    ValidationResponder {
        valid: false,
        entitlements: Vec::new(),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HeartbeatResponder;

impl Respond for HeartbeatResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let (product_slug, license_key) = request_identity(request);
        ResponseTemplate::new(200).set_body_json(json!({
            "object": "heartbeat",
            "received_at": "2025-01-01T00:00:00Z",
            "license": {
                "object": "license",
                "key": license_key,
                "status": "active",
                "starts_at": null,
                "expires_at": null,
                "mode": "hardware_locked",
                "plan_key": "pro",
                "seat_limit": 5,
                "active_seats": 1,
                "active_entitlements": [],
                "metadata": null,
                "product": { "slug": product_slug, "name": "Test App" }
            }
        }))
    }
}

pub fn heartbeat_responder() -> HeartbeatResponder {
    HeartbeatResponder
}
