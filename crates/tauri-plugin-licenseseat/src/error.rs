//! Plugin error types.

use serde::{Serialize, Serializer};

/// Result type for plugin operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Plugin error type that serializes to JSON for the frontend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error from the core SDK.
    #[error(transparent)]
    Sdk(#[from] licenseseat::Error),

    /// Tauri error.
    #[error(transparent)]
    Tauri(#[from] tauri::Error),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ErrorResponse {
            code: Option<String>,
            message: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            status: Option<u16>,
        }

        let response = match self {
            Error::Sdk(licenseseat::Error::Api { status, code, message, .. }) => {
                ErrorResponse {
                    code: code.clone(),
                    message: message.clone(),
                    status: Some(*status),
                }
            }
            Error::Sdk(e) => ErrorResponse {
                code: e.code().map(String::from),
                message: e.to_string(),
                status: e.status(),
            },
            Error::Tauri(e) => ErrorResponse {
                code: None,
                message: e.to_string(),
                status: None,
            },
        };

        response.serialize(serializer)
    }
}
