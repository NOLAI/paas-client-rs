use crate::oidc_auth::{authenticate_oidc, OIDCConfig};
use log::info;
use paas_api::status::SystemId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct TranscryptorOIDCConfig {
    configs: HashMap<SystemId, OIDCConfig>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct AuthStore {
    tokens: HashMap<SystemId, String>,
    expiry_times: HashMap<SystemId, u64>,
}

pub(crate) async fn ensure_authenticated(
    auth_store_path: &str,
    oidc_config_path: &str,
    system_id: &SystemId,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load or create auth store
    let auth_store = load_auth_store(auth_store_path)?;

    // Check if we have a valid token
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    if let (Some(token), Some(expiry_time)) = (
        auth_store.tokens.get(system_id),
        auth_store.expiry_times.get(system_id),
    ) {
        // Check if token is still valid (add some buffer before expiration)
        if *expiry_time > current_time + 60 {
            return Ok(token.clone());
        }

        // Token is expired, we need to re-authenticate
        info!(
            "Token for system '{}' has expired, initiating re-authentication...",
            system_id
        );
    } else {
        // No token found
        info!(
            "No valid token found for system '{}', initiating authentication...",
            system_id
        );
    }

    // Load OIDC config
    let oidc_config = load_oidc_config(oidc_config_path, system_id)?;

    // Authenticate and get new token with expiry
    let (token, expiry) = authenticate_oidc(&oidc_config).await?;

    // Save token with expiry
    save_token(auth_store_path, system_id, &token, expiry)?;

    Ok(token)
}

pub(crate) fn load_oidc_config(
    oidc_config_path: &str,
    system_id: &SystemId,
) -> Result<OIDCConfig, Box<dyn std::error::Error>> {
    let oidc_config_content = fs::read_to_string(oidc_config_path)
        .map_err(|e| format!("Failed to read OIDC config file: {}", e))?;

    let oidc_config: TranscryptorOIDCConfig = serde_json::from_str(&oidc_config_content)
        .map_err(|e| format!("Failed to parse OIDC config: {}", e))?;

    oidc_config
        .configs
        .get(system_id)
        .cloned()
        .ok_or_else(|| format!("Missing OIDC config for system '{}'", system_id).into())
}

pub(crate) fn save_token(
    auth_store_path: &str,
    system_id: &SystemId,
    token: &str,
    expiry: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth_store = load_auth_store(auth_store_path)?;

    auth_store
        .tokens
        .insert(system_id.to_string(), token.to_string());
    auth_store
        .expiry_times
        .insert(system_id.to_string(), expiry);

    let serialized = serde_json::to_string_pretty(&auth_store)?;
    fs::write(auth_store_path, serialized)?;
    info!("Token for system '{}' saved to auth store", system_id);

    Ok(())
}
pub(crate) fn load_auth_store(path: &str) -> Result<AuthStore, Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(AuthStore::default())
    }
}
