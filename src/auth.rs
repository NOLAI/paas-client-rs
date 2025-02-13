use async_trait::async_trait;
use paas_api::status::SystemId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Failed to get token: {0}")]
    TokenError(String),
    #[error("Failed to set header: {0}")]
    HeaderError(#[from] reqwest::header::InvalidHeaderValue),
}

#[async_trait]
pub trait Auth {
    fn token_type(&self) -> &str;
    async fn token(&self) -> Result<String, Box<dyn Error + Send + Sync>>;

    async fn authenticate(
        &self,
        headers: &mut reqwest::header::HeaderMap,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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
    async fn with_auth<A: Auth + Send + Sync + ?Sized>(
        self,
        auth: &A,
    ) -> Result<reqwest::RequestBuilder, AuthError>;
}

#[async_trait]
impl RequestBuilderExt for reqwest::RequestBuilder {
    async fn with_auth<A: Auth + Send + Sync + ?Sized>(
        self,
        auth: &A,
    ) -> Result<reqwest::RequestBuilder, AuthError> {
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

    async fn token(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        Ok(self.token.clone())
    }
}

pub struct SystemAuths(pub HashMap<SystemId, Box<dyn Auth + Send + Sync>>);

impl SystemAuths {
    pub fn new(auths: HashMap<SystemId, Box<dyn Auth + Send + Sync>>) -> Self {
        Self(auths)
    }
    pub fn from_auths<A: Auth + Send + Sync + 'static>(auths: HashMap<SystemId, A>) -> Self {
        Self::new(
            auths
                .into_iter()
                .map(|(id, auth)| (id, Box::new(auth) as Box<dyn Auth + Send + Sync>))
                .collect(),
        )
    }
    pub fn get(&self, system_id: &SystemId) -> Option<&(dyn Auth + Send + Sync)> {
        self.0.get(system_id).map(|auth| auth.as_ref())
    }
}
