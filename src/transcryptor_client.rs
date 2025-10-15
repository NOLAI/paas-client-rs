use crate::auth::{Auth, AuthError, RequestBuilderExt};
use libpep::distributed::key_blinding::SessionKeyShares;
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::{EncryptedAttribute, EncryptedPseudonym};
use libpep::high_level::ops::EncryptedData;
use paas_api::config::{PAASConfig, TranscryptorConfig};
use paas_api::sessions::{EndSessionRequest, SessionResponse, StartSessionResponse};
use paas_api::status::{StatusResponse, VersionInfo};
use paas_api::transcrypt::{
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse, RekeyBatchRequest, RekeyBatchResponse, RekeyRequest, RekeyResponse,
    TranscryptionRequest, TranscryptionResponse,
};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum TranscryptorError {
    #[error(transparent)]
    AuthError(#[from] AuthError),
    #[error(transparent)]
    NetworkError(#[from] reqwest::Error),
    #[error("Authentication required")]
    Unauthorized,
    #[error("Transcryption not allowed: {0}")]
    NotAllowed(String),
    #[error("Invalid or expired session: {0}")]
    InvalidSession(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Server error: {0}")]
    ServerError(String),

    #[error("No active session to end")]
    NoSessionToEnd,
    #[error(
        "Client version {client_version} is incompatible with server version {server_version} (min. supported version {server_min_supported_version})"
    )]
    IncompatibleClientVersionError {
        client_version: String,
        server_version: String,
        server_min_supported_version: String,
    },
    #[error("Inconsistent system name (configured: {configured_name}, responded: {responded_name}")]
    InconsistentSystemNameError {
        configured_name: String,
        responded_name: String,
    },
    #[error("Inconsistent system name ({name})")]
    InvalidSystemNameError { name: String },
    #[error("Inconsistent configuration (configured: {configured_url}, responded: {responded_url}")]
    InconsistentUrlError {
        configured_url: String,
        responded_url: String,
    },
    #[error("URL must use HTTPS protocol, got: {scheme}")]
    NonHttpsUrlError { scheme: String },
}

#[derive(Debug, serde::Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Clone)]
/// A client that communicates with a single Transcryptor.
pub struct TranscryptorClient {
    pub(crate) config: TranscryptorConfig,
    pub(crate) session_id: Option<EncryptionContext>,
    pub(crate) sks: Option<SessionKeyShares>,
    auth: Arc<dyn Auth>,
}
impl TranscryptorClient {
    /// Create a new TranscryptorClient with the given configuration.
    pub async fn new(
        config: TranscryptorConfig,
        auth: Arc<dyn Auth>,
    ) -> Result<TranscryptorClient, TranscryptorError> {
        if config.url.scheme() != "https" {
            return Err(TranscryptorError::NonHttpsUrlError {
                scheme: config.url.scheme().to_string(),
            });
        }

        let mut client = Self {
            config,
            auth,
            session_id: None,
            sks: None,
        };
        client.check_status().await.and(Ok(client))
    }

    /// Create a new TranscryptorClient with the given configuration, allowing HTTP URLs.
    /// This should only be used for testing purposes.
    #[doc(hidden)]
    pub async fn new_allow_http(
        config: TranscryptorConfig,
        auth: Arc<dyn Auth>,
    ) -> Result<TranscryptorClient, TranscryptorError> {
        let mut client = Self {
            config,
            auth,
            session_id: None,
            sks: None,
        };
        client.check_status().await.and(Ok(client))
    }

    /// Restore a TranscryptorClient with an existing session.
    pub async fn restore(
        config: TranscryptorConfig,
        auth: Arc<dyn Auth>,
        session_id: EncryptionContext,
        sks: SessionKeyShares,
    ) -> Result<TranscryptorClient, TranscryptorError> {
        if config.url.scheme() != "https" {
            return Err(TranscryptorError::NonHttpsUrlError {
                scheme: config.url.scheme().to_string(),
            });
        }

        let mut client = Self {
            config,
            auth,
            session_id: Some(session_id),
            sks: Some(sks),
        };
        client.check_status().await.and(Ok(client))
    }
    pub fn dump(
        &self,
    ) -> (
        TranscryptorConfig,
        Option<EncryptionContext>,
        Option<SessionKeyShares>,
    ) {
        (self.config.clone(), self.session_id.clone(), self.sks)
    }
    fn make_url(&self, path: &str) -> String {
        format!(
            "{}{}{}",
            self.config.url.as_str().trim_end_matches('/'),
            paas_api::paths::API_BASE,
            path
        )
    }
    async fn process_response<T>(&self, response: reqwest::Response) -> Result<T, TranscryptorError>
    where
        T: serde::de::DeserializeOwned,
    {
        if let Err(error) = response.error_for_status_ref() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            let error_message = serde_json::from_str::<ErrorResponse>(&body)
                .map(|r| r.error)
                .unwrap_or(body);

            let error = match status.as_u16() {
                401 => TranscryptorError::Unauthorized,
                403 => TranscryptorError::NotAllowed(error_message),
                404 => TranscryptorError::InvalidSession(error_message),
                400 => TranscryptorError::BadRequest(error_message),
                500..=599 => TranscryptorError::ServerError(error_message),
                _ => TranscryptorError::NetworkError(error),
            };

            return Err(error);
        }

        let data = response.json::<T>().await?;
        Ok(data)
    }

    /// Check the status of the transcryptor.
    pub async fn check_status(&mut self) -> Result<(), TranscryptorError> {
        let response = reqwest::Client::new()
            .get(self.make_url(paas_api::paths::STATUS))
            .send()
            .await?;

        let status = self.process_response::<StatusResponse>(response).await?;

        let client_version = VersionInfo::default();
        if !status.version_info.is_compatible_with(&client_version) {
            return Err(TranscryptorError::IncompatibleClientVersionError {
                client_version: client_version.protocol_version.to_string(),
                server_version: status.version_info.protocol_version.to_string(),
                server_min_supported_version: status.version_info.min_supported_version.to_string(),
            });
        };

        if status.system_id != self.config.system_id {
            return Err(TranscryptorError::InconsistentSystemNameError {
                responded_name: status.system_id,
                configured_name: self.config.system_id.clone(),
            });
        }

        Ok(())
    }

    /// Verify the config of a system
    pub async fn check_config(&mut self) -> Result<PAASConfig, TranscryptorError> {
        let response = reqwest::Client::new()
            .get(self.make_url(paas_api::paths::CONFIG))
            .with_auth(&self.auth)
            .await?
            .send()
            .await?;

        let config = self.process_response::<PAASConfig>(response).await?;

        let ts_config = config
            .transcryptors
            .iter()
            .find(|tc| tc.system_id == self.config.system_id)
            .ok_or_else(|| TranscryptorError::InvalidSystemNameError {
                name: self.config.system_id.clone(),
            })?;

        if ts_config.url != self.config.url {
            return Err(TranscryptorError::InconsistentUrlError {
                configured_url: self.config.url.to_string(),
                responded_url: ts_config.url.to_string(),
            });
        }

        Ok(config)
    }

    /// Start a new session with the transcryptor.
    pub async fn start_session(
        &mut self,
    ) -> Result<(EncryptionContext, SessionKeyShares), TranscryptorError> {
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::SESSIONS_START))
            .with_auth(&self.auth)
            .await?
            .send()
            .await?;

        let session = self
            .process_response::<StartSessionResponse>(response)
            .await?;

        self.session_id = Some(session.session_id.clone());
        self.sks = Some(session.session_key_shares);
        Ok((session.session_id, session.session_key_shares))
    }

    /// Get all currently active sessions.
    pub async fn get_sessions(&mut self) -> Result<Vec<EncryptionContext>, TranscryptorError> {
        let response = reqwest::Client::new()
            .get(self.make_url(paas_api::paths::SESSIONS_GET))
            .with_auth(&self.auth)
            .await?
            .send()
            .await?;

        let sessions = self.process_response::<SessionResponse>(response).await?;
        Ok(sessions.sessions)
    }

    /// End a session.
    /// Notice that this is not automatically called, but proper clients should close their sessions when they are done.
    pub async fn end_session(&mut self) -> Result<(), TranscryptorError> {
        let request = EndSessionRequest {
            session_id: self
                .session_id
                .clone()
                .ok_or(TranscryptorError::NoSessionToEnd)?,
        };
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::SESSIONS_END))
            .with_auth(&self.auth)
            .await?
            .json(&request)
            .send()
            .await?;

        let _ = self
            .process_response::<StartSessionResponse>(response)
            .await?;

        self.session_id = None;
        self.sks = None;

        Ok(())
    }

    /// Ask the transcryptor pseudonymize an encrypted pseudonym.
    pub async fn pseudonymize(
        &self,
        encrypted_pseudonym: &EncryptedPseudonym,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<EncryptedPseudonym, TranscryptorError> {
        let request = PseudonymizationRequest {
            encrypted_pseudonym: *encrypted_pseudonym,
            domain_from: domain_from.clone(),
            domain_to: domain_to.clone(),
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::PSEUDONYMIZE))
            .with_auth(&self.auth)
            .await?
            .json(&request)
            .send()
            .await?;
        let pseudo_response = self
            .process_response::<PseudonymizationResponse>(response)
            .await?;
        Ok(pseudo_response.encrypted_pseudonym)
    }

    /// Ask the transcryptor to pseudonymize a batch of encrypted pseudonyms.
    pub async fn pseudonymize_batch(
        &self,
        encrypted_pseudonyms: &[EncryptedPseudonym],
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<Vec<EncryptedPseudonym>, TranscryptorError> {
        let request = PseudonymizationBatchRequest {
            encrypted_pseudonyms: encrypted_pseudonyms.to_vec(),
            domain_from: domain_from.clone(),
            domain_to: domain_to.clone(),
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::PSEUDONYMIZE_BATCH))
            .with_auth(&self.auth)
            .await?
            .json(&request)
            .send()
            .await?;
        let pseudo_response = self
            .process_response::<PseudonymizationBatchResponse>(response)
            .await?;
        Ok(pseudo_response.encrypted_pseudonyms)
    }

    /// Ask the transcryptor rekey an encrypted data point.
    pub async fn rekey(
        &self,
        encrypted_attribute: &EncryptedAttribute,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<EncryptedAttribute, TranscryptorError> {
        let request = RekeyRequest {
            encrypted_attribute: *encrypted_attribute,
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::REKEY))
            .with_auth(&self.auth)
            .await?
            .json(&request)
            .send()
            .await?;
        let rekey_response = self.process_response::<RekeyResponse>(response).await?;
        Ok(rekey_response.encrypted_attribute)
    }

    /// Ask the transcryptor to rekey a batch of encrypted data points.
    pub async fn rekey_batch(
        &self,
        encrypt_attributes: &[EncryptedAttribute],
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<Vec<EncryptedAttribute>, TranscryptorError> {
        let request = RekeyBatchRequest {
            encrypted_attributes: encrypt_attributes.to_vec(),
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::REKEY_BATCH))
            .with_auth(&self.auth)
            .await?
            .json(&request)
            .send()
            .await?;
        let rekey_response = self
            .process_response::<RekeyBatchResponse>(response)
            .await?;
        Ok(rekey_response.encrypted_attributes)
    }

    /// Ask the transcryptor to transcrypt data consisting of multiple pseudonyms and data points belonging to different entities.
    pub async fn transcrypt(
        &self,
        encrypted: &[EncryptedData],
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<Vec<EncryptedData>, TranscryptorError> {
        let request = TranscryptionRequest {
            encrypted: encrypted.to_vec(),
            domain_from: domain_from.clone(),
            domain_to: domain_to.clone(),
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(self.make_url(paas_api::paths::TRANSCRYPT))
            .with_auth(&self.auth)
            .await?
            .json(&request)
            .send()
            .await?;
        let transcrypt_response = self
            .process_response::<TranscryptionResponse>(response)
            .await?;
        Ok(transcrypt_response.encrypted)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use mockito::Server;

    use super::*;

    struct TestAuth;

    #[async_trait]
    impl Auth for TestAuth {
        fn token_type(&self) -> &str {
            "test"
        }

        async fn token(&self) -> Result<String, Box<dyn core::error::Error>> {
            Ok("test".to_owned())
        }
    }

    #[tokio::test]
    async fn error_mapping() {
        let config = TranscryptorConfig {
            system_id: "test".to_owned(),
            url: "https://example.com".parse().unwrap(),
        };
        let auth = Arc::new(TestAuth);
        let t_c = TranscryptorClient {
            config,
            session_id: None,
            sks: None,
            auth,
        };

        let mut server = Server::new_async().await;

        server
            .mock("GET", "/")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"error":"Unknown or expired session: Target session not owned by user"}"#,
            )
            .create_async()
            .await;

        let response = reqwest::get(server.url()).await;

        let x = t_c
            .process_response::<StatusResponse>(response.unwrap())
            .await;

        let err_str = "Unknown or expired session: Target session not owned by user";

        #[allow(clippy::assertions_on_constants)]
        match x {
            Err(TranscryptorError::InvalidSession(err)) if err == err_str => assert!(true),
            _ => assert!(false),
        }
    }
}
