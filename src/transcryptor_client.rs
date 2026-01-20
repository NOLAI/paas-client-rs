use crate::auth::{Auth, AuthError, RequestBuilderExt};
use crate::variants::{EncryptedAttributeVariant, EncryptedDataVariant, EncryptedPseudonymVariant};
use libpep::core::transcryption::{EncryptionContext, PseudonymizationDomain};
use libpep::distributed::server::keys::SessionKeyShares;
use paas_api::config::{PAASConfig, TranscryptorConfig};
use paas_api::sessions::{EndSessionRequest, SessionResponse, StartSessionResponse};
use paas_api::status::{StatusResponse, VersionInfo};
use paas_api::transcrypt::{
    JsonTranscryptionBatchRequest, JsonTranscryptionBatchResponse, JsonTranscryptionRequest,
    JsonTranscryptionResponse, LongPseudonymizationBatchRequest, LongPseudonymizationBatchResponse,
    LongPseudonymizationRequest, LongPseudonymizationResponse, LongRekeyBatchRequest,
    LongRekeyBatchResponse, LongRekeyRequest, LongRekeyResponse, LongTranscryptionBatchRequest,
    LongTranscryptionBatchResponse, LongTranscryptionRequest, LongTranscryptionResponse,
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse, RekeyBatchRequest, RekeyBatchResponse, RekeyRequest, RekeyResponse,
    TranscryptionBatchRequest, TranscryptionBatchResponse, TranscryptionRequest,
    TranscryptionResponse,
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
    #[error("Unexpected encrypted data variant type in response")]
    UnexpectedVariantType,
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
        encrypted_pseudonym: &EncryptedPseudonymVariant,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<EncryptedPseudonymVariant, TranscryptorError> {
        match encrypted_pseudonym {
            EncryptedPseudonymVariant::Normal(ep) => {
                let request = PseudonymizationRequest {
                    encrypted_pseudonym: *ep,
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
                Ok(EncryptedPseudonymVariant::Normal(
                    pseudo_response.encrypted_pseudonym,
                ))
            }
            EncryptedPseudonymVariant::Long(lep) => {
                let request = LongPseudonymizationRequest {
                    encrypted_pseudonym: lep.clone(),
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::PSEUDONYMIZE_LONG))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let pseudo_response = self
                    .process_response::<LongPseudonymizationResponse>(response)
                    .await?;
                Ok(EncryptedPseudonymVariant::Long(
                    pseudo_response.encrypted_pseudonym,
                ))
            }
        }
    }

    /// Ask the transcryptor to pseudonymize a batch of encrypted pseudonyms.
    pub async fn pseudonymize_batch(
        &self,
        encrypted_pseudonyms: &[EncryptedPseudonymVariant],
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<Vec<EncryptedPseudonymVariant>, TranscryptorError> {
        if encrypted_pseudonyms.is_empty() {
            return Ok(vec![]);
        }

        match &encrypted_pseudonyms[0] {
            EncryptedPseudonymVariant::Normal(_) => {
                let Normal_pseudonyms: Vec<_> = encrypted_pseudonyms
                    .iter()
                    .map(|v| match v {
                        EncryptedPseudonymVariant::Normal(ep) => *ep,
                        EncryptedPseudonymVariant::Long(_) => {
                            panic!("Mixed variant types in batch")
                        }
                    })
                    .collect();
                let request = PseudonymizationBatchRequest {
                    encrypted_pseudonyms: Normal_pseudonyms,
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
                Ok(pseudo_response
                    .encrypted_pseudonyms
                    .into_iter()
                    .map(EncryptedPseudonymVariant::Normal)
                    .collect())
            }
            EncryptedPseudonymVariant::Long(_) => {
                let long_pseudonyms: Vec<_> = encrypted_pseudonyms
                    .iter()
                    .map(|v| match v {
                        EncryptedPseudonymVariant::Long(lep) => lep.clone(),
                        EncryptedPseudonymVariant::Normal(_) => {
                            panic!("Mixed variant types in batch")
                        }
                    })
                    .collect();
                let request = LongPseudonymizationBatchRequest {
                    encrypted_pseudonyms: long_pseudonyms,
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::PSEUDONYMIZE_BATCH_LONG))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let pseudo_response = self
                    .process_response::<LongPseudonymizationBatchResponse>(response)
                    .await?;
                Ok(pseudo_response
                    .encrypted_pseudonyms
                    .into_iter()
                    .map(EncryptedPseudonymVariant::Long)
                    .collect())
            }
        }
    }

    /// Ask the transcryptor rekey an encrypted data point.
    pub async fn rekey(
        &self,
        encrypted_attribute: &EncryptedAttributeVariant,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<EncryptedAttributeVariant, TranscryptorError> {
        match encrypted_attribute {
            EncryptedAttributeVariant::Normal(ea) => {
                let request = RekeyRequest {
                    encrypted_attribute: *ea,
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
                Ok(EncryptedAttributeVariant::Normal(
                    rekey_response.encrypted_attribute,
                ))
            }
            EncryptedAttributeVariant::Long(lea) => {
                let request = LongRekeyRequest {
                    encrypted_attribute: lea.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::REKEY_LONG))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let rekey_response = self.process_response::<LongRekeyResponse>(response).await?;
                Ok(EncryptedAttributeVariant::Long(
                    rekey_response.encrypted_attribute,
                ))
            }
        }
    }

    /// Ask the transcryptor to rekey a batch of encrypted data points.
    pub async fn rekey_batch(
        &self,
        encrypted_attributes: &[EncryptedAttributeVariant],
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<Vec<EncryptedAttributeVariant>, TranscryptorError> {
        if encrypted_attributes.is_empty() {
            return Ok(vec![]);
        }

        match &encrypted_attributes[0] {
            EncryptedAttributeVariant::Normal(_) => {
                let Normal_attributes: Vec<_> = encrypted_attributes
                    .iter()
                    .map(|v| match v {
                        EncryptedAttributeVariant::Normal(ea) => *ea,
                        EncryptedAttributeVariant::Long(_) => {
                            panic!("Mixed variant types in batch")
                        }
                    })
                    .collect();
                let request = RekeyBatchRequest {
                    encrypted_attributes: Normal_attributes,
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
                Ok(rekey_response
                    .encrypted_attributes
                    .into_iter()
                    .map(EncryptedAttributeVariant::Normal)
                    .collect())
            }
            EncryptedAttributeVariant::Long(_) => {
                let long_attributes: Vec<_> = encrypted_attributes
                    .iter()
                    .map(|v| match v {
                        EncryptedAttributeVariant::Long(lea) => lea.clone(),
                        EncryptedAttributeVariant::Normal(_) => {
                            panic!("Mixed variant types in batch")
                        }
                    })
                    .collect();
                let request = LongRekeyBatchRequest {
                    encrypted_attributes: long_attributes,
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::REKEY_BATCH_LONG))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let rekey_response = self
                    .process_response::<LongRekeyBatchResponse>(response)
                    .await?;
                Ok(rekey_response
                    .encrypted_attributes
                    .into_iter()
                    .map(EncryptedAttributeVariant::Long)
                    .collect())
            }
        }
    }

    /// Ask the transcryptor to transcrypt data consisting of multiple pseudonyms and data points belonging to different entities.
    pub async fn transcrypt(
        &self,
        encrypted: &EncryptedDataVariant,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<EncryptedDataVariant, TranscryptorError> {
        match encrypted {
            EncryptedDataVariant::Normal(ed) => {
                let request = TranscryptionRequest {
                    encrypted: ed.clone(),
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
                Ok(EncryptedDataVariant::Normal(transcrypt_response.encrypted))
            }
            EncryptedDataVariant::Long(led) => {
                let request = LongTranscryptionRequest {
                    encrypted: led.clone(),
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::TRANSCRYPT_LONG))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let transcrypt_response = self
                    .process_response::<LongTranscryptionResponse>(response)
                    .await?;
                Ok(EncryptedDataVariant::Long(transcrypt_response.encrypted))
            }
            EncryptedDataVariant::Json(ejson) => {
                let request = JsonTranscryptionRequest {
                    encrypted: ejson.clone(),
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::TRANSCRYPT_JSON))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let transcrypt_response = self
                    .process_response::<JsonTranscryptionResponse>(response)
                    .await?;
                Ok(EncryptedDataVariant::Json(transcrypt_response.encrypted))
            }
        }
    }

    /// Ask the transcryptor to transcrypt a batch of encrypted data items.
    pub async fn transcrypt_batch(
        &self,
        encrypted: &[EncryptedDataVariant],
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> Result<Vec<EncryptedDataVariant>, TranscryptorError> {
        if encrypted.is_empty() {
            return Ok(vec![]);
        }

        match &encrypted[0] {
            EncryptedDataVariant::Normal(_) => {
                let Normal_data: Vec<_> = encrypted
                    .iter()
                    .map(|v| match v {
                        EncryptedDataVariant::Normal(ed) => ed.clone(),
                        _ => panic!("Mixed variant types in batch"),
                    })
                    .collect();
                let request = TranscryptionBatchRequest {
                    encrypted: Normal_data,
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::TRANSCRYPT_BATCH))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let transcrypt_response = self
                    .process_response::<TranscryptionBatchResponse>(response)
                    .await?;
                Ok(transcrypt_response
                    .encrypted
                    .into_iter()
                    .map(EncryptedDataVariant::Normal)
                    .collect())
            }
            EncryptedDataVariant::Long(_) => {
                let long_data: Vec<_> = encrypted
                    .iter()
                    .map(|v| match v {
                        EncryptedDataVariant::Long(led) => led.clone(),
                        _ => panic!("Mixed variant types in batch"),
                    })
                    .collect();
                let request = LongTranscryptionBatchRequest {
                    encrypted: long_data,
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::TRANSCRYPT_BATCH_LONG))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let transcrypt_response = self
                    .process_response::<LongTranscryptionBatchResponse>(response)
                    .await?;
                Ok(transcrypt_response
                    .encrypted
                    .into_iter()
                    .map(EncryptedDataVariant::Long)
                    .collect())
            }
            EncryptedDataVariant::Json(_) => {
                let json_data: Vec<_> = encrypted
                    .iter()
                    .map(|v| match v {
                        EncryptedDataVariant::Json(ejson) => ejson.clone(),
                        _ => panic!("Mixed variant types in batch"),
                    })
                    .collect();
                let request = JsonTranscryptionBatchRequest {
                    encrypted: json_data,
                    domain_from: domain_from.clone(),
                    domain_to: domain_to.clone(),
                    session_from: session_from.clone(),
                    session_to: session_to.clone(),
                };
                let response = reqwest::Client::new()
                    .post(self.make_url(paas_api::paths::TRANSCRYPT_JSON_BATCH))
                    .with_auth(&self.auth)
                    .await?
                    .json(&request)
                    .send()
                    .await?;
                let transcrypt_response = self
                    .process_response::<JsonTranscryptionBatchResponse>(response)
                    .await?;
                Ok(transcrypt_response
                    .encrypted
                    .into_iter()
                    .map(EncryptedDataVariant::Json)
                    .collect())
            }
        }
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
