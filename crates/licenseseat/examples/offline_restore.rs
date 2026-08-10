//! Exercise an online activation followed by signed offline restoration.
//!
//! Required environment variables:
//!
//! ```text
//! LICENSESEAT_API_KEY=pk_live_xxx
//! LICENSESEAT_PRODUCT_SLUG=your-product
//! LICENSESEAT_LICENSE_KEY=customer-license
//! LICENSESEAT_SIGNING_PUBLIC_KEY=base64-ed25519-public-key
//! LICENSESEAT_SIGNING_KEY_ID=key-id
//! ```
//!
//! `LICENSESEAT_BASE_URL` defaults to the production API. Set the optional
//! `LICENSESEAT_ENTITLEMENT_KEY` to prove a specific offline entitlement.

use licenseseat::{Config, LicenseSeat, LicenseStatus, OfflineFallbackMode};
use std::{env, time::Duration};

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} environment variable required"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = required("LICENSESEAT_API_KEY");
    let product_slug = required("LICENSESEAT_PRODUCT_SLUG");
    let license_key = required("LICENSESEAT_LICENSE_KEY");
    let signing_public_key = required("LICENSESEAT_SIGNING_PUBLIC_KEY");
    let signing_key_id = required("LICENSESEAT_SIGNING_KEY_ID");
    let api_base_url = env::var("LICENSESEAT_BASE_URL")
        .unwrap_or_else(|_| "https://licenseseat.com/api/v1".into());
    let storage = tempfile::tempdir()?;

    let config = Config {
        api_key,
        product_slug,
        api_base_url,
        storage_path: Some(storage.path().join("state")),
        signing_public_key: Some(signing_public_key),
        signing_key_id: Some(signing_key_id),
        offline_fallback_mode: OfflineFallbackMode::NetworkOnly,
        max_offline_days: 7,
        auto_validate_interval: Duration::ZERO,
        heartbeat_interval: Duration::ZERO,
        network_recheck_interval: Duration::ZERO,
        offline_token_refresh_interval: Duration::ZERO,
        ..Default::default()
    };

    let online = LicenseSeat::try_new(config.clone())?;
    online.activate(&license_key).await?;
    online.sync_offline_assets().await?;
    let online_validation = online.validate().await?;
    if !online_validation.valid {
        return Err("online validation did not grant the license".into());
    }
    drop(online);

    let mut offline_config = config;
    offline_config.api_base_url = "http://127.0.0.1:9".into();
    let offline = LicenseSeat::try_new(offline_config)?;
    let restored = offline.restore_license().await;
    if !restored.restored || !matches!(&restored.status, LicenseStatus::OfflineValid { .. }) {
        return Err(format!("signed offline restoration failed: {restored:?}").into());
    }

    if let Ok(entitlement) = env::var("LICENSESEAT_ENTITLEMENT_KEY") {
        let status = offline.check_entitlement(&entitlement);
        if !status.active {
            return Err(format!("offline entitlement {entitlement:?} was not granted").into());
        }
    }

    println!("Signed offline restoration succeeded.");
    Ok(())
}
