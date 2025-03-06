use crate::oidc_auth::{authenticate_oidc, OIDCConfig};
use log::info;
use paas_api::status::SystemId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Represents different types of authentication methods
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) enum AuthConfig {
    /// OpenID Connect authentication
    Oidc(OIDCConfig),
    /// Simple bearer token authentication
    BearerToken {
        /// The bearer token
        token: String,
    },
}

/// The configuration for all transcryptor systems
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct TranscryptorAuthConfig {
    auth: HashMap<SystemId, AuthConfig>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct JWTAuthStore {
    tokens: HashMap<SystemId, String>,
    expiry_times: HashMap<SystemId, Option<u64>>,
}

impl TranscryptorAuthConfig {
    pub fn get_config(&self, system_id: &SystemId) -> Option<&AuthConfig> {
        self.auth.get(system_id)
    }
}

pub(crate) async fn ensure_authenticated(
    auth_store_path: &str,
    auth_config_path: &str,
    system_id: &SystemId,
) -> Result<String, Box<dyn std::error::Error>> {
    let auth_config = load_auth_config(auth_config_path, system_id)?;

    // For bearer token auth, skip the auth store entirely
    if let AuthConfig::BearerToken { token } = auth_config {
        // For bearer token, we use it directly without storing in auth store
        info!("Using bearer token for system '{}'", system_id);
        return Ok(token);
    }

    // For OIDC, continue with auth store flow
    // Load or create auth store
    let auth_store = load_auth_store(auth_store_path)?;

    // Check if we have a valid token
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    if let Some(token) = auth_store.tokens.get(system_id) {
        // Check if token has an expiry time
        match auth_store.expiry_times.get(system_id).and_then(|t| *t) {
            // If we have an expiry time, check if it's still valid
            Some(expiry_time) if expiry_time > current_time + 60 => {
                return Ok(token.clone());
            }
            Some(_) => {
                // Token is expired, we need to re-authenticate
                info!(
                    "Token for system '{}' has expired, initiating re-authentication...",
                    system_id
                );
            }
            // If there's no expiry (None), the token is always valid
            None => {
                return Ok(token.clone());
            }
        }
    } else {
        // No token found
        info!(
            "No valid token found for system '{}', initiating authentication...",
            system_id
        );
    }

    // At this point, we have an OIDC config and need to authenticate
    if let AuthConfig::Oidc(oidc_config) = auth_config {
        // Authenticate and get new token with expiry
        let (token, expiry) = authenticate_oidc(&oidc_config).await?;

        // Save token with expiry
        save_token(auth_store_path, system_id, &token, Some(expiry))?;

        Ok(token)
    } else {
        // This should never happen due to the early return for BearerToken
        unreachable!("Unexpected auth config type");
    }
}

pub(crate) fn load_auth_config(
    auth_config_path: &str,
    system_id: &SystemId,
) -> Result<AuthConfig, Box<dyn std::error::Error>> {
    let auth_config_content = fs::read_to_string(auth_config_path)
        .map_err(|e| format!("Failed to read auth config file: {}", e))?;

    let auth_config: TranscryptorAuthConfig = serde_json::from_str(&auth_config_content)
        .map_err(|e| format!("Failed to parse auth config: {}", e))?;

    auth_config
        .get_config(system_id)
        .cloned()
        .ok_or_else(|| format!("Missing auth config for system '{}'", system_id).into())
}

pub(crate) fn save_token(
    auth_store_path: &str,
    system_id: &SystemId,
    token: &str,
    expiry: Option<u64>,
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

    if expiry.is_some() {
        info!(
            "Token for system '{}' saved to auth store with expiry",
            system_id
        );
    } else {
        info!(
            "Token for system '{}' saved to auth store (no expiry)",
            system_id
        );
    }

    Ok(())
}

pub(crate) fn load_auth_store(path: &str) -> Result<JWTAuthStore, Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(JWTAuthStore::default())
    }
}
