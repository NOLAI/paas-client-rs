use async_trait::async_trait;
use paas_api::status::SystemId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Failed to get token: {0}")]
    TokenError(String),
    #[error("Failed to set header: {0}")]
    HeaderError(#[from] reqwest::header::InvalidHeaderValue),
}

#[async_trait]
pub trait Auth: Send + Sync + 'static {
    fn token_type(&self) -> &str;
    async fn token(&self) -> Result<String, Box<dyn Error>>;

    async fn authenticate(
        &self,
        headers: &mut reqwest::header::HeaderMap,
    ) -> Result<(), Box<dyn Error>> {
        let auth_value = format!("{} {}", self.token_type(), self.token().await?);
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&auth_value)?,
        );
        Ok(())
    }
}

#[async_trait]
pub(crate) trait RequestBuilderExt {
    async fn with_auth(self, auth: &Arc<dyn Auth>) -> Result<reqwest::RequestBuilder, AuthError>;
}

#[async_trait]
impl RequestBuilderExt for reqwest::RequestBuilder {
    async fn with_auth(self, auth: &Arc<dyn Auth>) -> Result<reqwest::RequestBuilder, AuthError> {
        let auth_value = format!(
            "{} {}",
            auth.token_type(),
            auth.token()
                .await
                .map_err(|e| AuthError::TokenError(e.to_string()))?
        );
        Ok(self.header(reqwest::header::AUTHORIZATION, auth_value))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BearerTokenAuth {
    token: String,
}

impl BearerTokenAuth {
    pub fn new(token: String) -> BearerTokenAuth {
        BearerTokenAuth { token }
    }
}

#[async_trait]
impl Auth for BearerTokenAuth {
    fn token_type(&self) -> &str {
        "Bearer"
    }

    async fn token(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.token.clone())
    }
}

pub struct SystemAuths(pub HashMap<SystemId, Arc<dyn Auth>>);

impl SystemAuths {
    pub fn new(auths: HashMap<SystemId, Arc<dyn Auth>>) -> Self {
        Self(auths)
    }

    pub fn from_auths<A: Auth>(auths: HashMap<SystemId, A>) -> Self {
        Self::new(
            auths
                .into_iter()
                .map(|(id, auth)| (id, Arc::new(auth) as Arc<dyn Auth>))
                .collect(),
        )
    }

    pub fn get(&self, system_id: &SystemId) -> Option<Arc<dyn Auth>> {
        self.0.get(system_id).map(Arc::clone)
    }
}
