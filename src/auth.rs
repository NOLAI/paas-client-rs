use crate::transcryptor_client::AuthToken;
use paas_api::status::SystemId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens(pub HashMap<SystemId, AuthToken>);

impl AuthTokens {
    pub fn get(&self, system_id: &SystemId) -> Option<&AuthToken> {
        self.0.get(system_id)
    }
}

impl FromStr for AuthTokens {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let map: HashMap<SystemId, AuthToken> = serde_json::from_str(s)?;
        Ok(Self(map))
    }
}
