use crate::auth::SystemAuths;
use crate::sessions::EncryptionContexts;
use crate::transcryptor_client::{TranscryptorClient, TranscryptorError};
use libpep::client::{Client, Distributed};
use libpep::data::traits::{
    Encryptable, Encrypted, HasStructure, Pseudonymizable, Rekeyable, Transcryptable,
};
use libpep::factors::PseudonymizationDomain;
use libpep::keys::distribution::SessionKeyShares;
use libpep::keys::{KeyProvider, SessionKeys};
use libpep::transcryptor::BatchError;
use paas_api::config::PAASConfig;
use paas_api::paths::ApiPath;
use paas_api::status::SystemId;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum PseudonymServiceError {
    #[error(transparent)]
    TranscryptorError(#[from] TranscryptorError),
    #[error(transparent)]
    BatchError(#[from] BatchError),
    #[error("No auth found for system {0}")]
    MissingAuth(SystemId),
    #[error("No session found for system {0}")]
    MissingSession(SystemId),
    #[error("No session key share found for system {0}")]
    MissingSessionKeyShares(SystemId),
    #[error("PEP crypto client not initialized")]
    UninitializedClient,
    #[error("Transcryptor does not have session")]
    UninitializedTranscryptor,
    #[error("Inconsistent config received from {system}")]
    InconsistentConfig { system: SystemId },
}

#[derive(Clone)]
pub struct PseudonymService {
    pub(crate) config: PAASConfig,
    pub(crate) transcryptors: Vec<TranscryptorClient>,
    pep_crypto_client: Option<Client>,
}

pub type SessionKeySharess = HashMap<SystemId, SessionKeyShares>;

/// Convert encrypted pseudonyms into your own pseudonyms, using the [PseudonymService].
/// The service will communicate with the configured transcryptors, and wraps around a [Client] for cryptographic operations.
impl PseudonymService {
    /// Create a new PseudonymService with the given configuration.
    pub async fn new(
        config: PAASConfig,
        auths: SystemAuths,
    ) -> Result<Self, PseudonymServiceError> {
        let transcryptors =
            futures::future::try_join_all(config.transcryptors.iter().map(|c| async {
                let auth = auths
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingAuth(c.system_id.clone()))?;

                let mut client = TranscryptorClient::new(c.clone(), auth)
                    .await
                    .map_err(PseudonymServiceError::TranscryptorError)?;

                let reported_config = client
                    .check_config()
                    .await
                    .map_err(PseudonymServiceError::TranscryptorError)?;

                if reported_config != config {
                    return Err(PseudonymServiceError::InconsistentConfig {
                        system: c.system_id.clone(),
                    });
                }

                Ok(client)
            }))
            .await?;

        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: None,
        })
    }

    /// Create a new PseudonymService with the given configuration, allowing HTTP URLs.
    /// This should only be used for testing purposes.
    #[doc(hidden)]
    pub async fn new_allow_http(
        config: PAASConfig,
        auths: SystemAuths,
    ) -> Result<Self, PseudonymServiceError> {
        let transcryptors =
            futures::future::try_join_all(config.transcryptors.iter().map(|c| async {
                let auth = auths
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingAuth(c.system_id.clone()))?;

                let mut client = TranscryptorClient::new_allow_http(c.clone(), auth)
                    .await
                    .map_err(PseudonymServiceError::TranscryptorError)?;

                let reported_config = client
                    .check_config()
                    .await
                    .map_err(PseudonymServiceError::TranscryptorError)?;

                if reported_config != config {
                    return Err(PseudonymServiceError::InconsistentConfig {
                        system: c.system_id.clone(),
                    });
                }

                Ok(client)
            }))
            .await?;

        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: None,
        })
    }

    /// Restore a [PseudonymService] from a dumped state.
    pub async fn restore(
        config: PAASConfig,
        auths: SystemAuths,
        session_ids: EncryptionContexts,
        session_key_shares: SessionKeySharess,
        session_keys: SessionKeys,
    ) -> Result<Self, PseudonymServiceError> {
        let transcryptors =
            futures::future::try_join_all(config.transcryptors.iter().map(|c| async {
                let auth = auths
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingAuth(c.system_id.clone()))?;

                let session_id = session_ids
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingSession(c.system_id.clone()))?;

                let sks = session_key_shares.get(&c.system_id).ok_or_else(|| {
                    PseudonymServiceError::MissingSessionKeyShares(c.system_id.clone())
                })?;

                let mut client =
                    TranscryptorClient::restore(c.clone(), auth, session_id.clone(), *sks)
                        .await
                        .map_err(PseudonymServiceError::TranscryptorError)?;

                let reported_config = client
                    .check_config()
                    .await
                    .map_err(PseudonymServiceError::TranscryptorError)?;

                if reported_config != config {
                    return Err(PseudonymServiceError::InconsistentConfig {
                        system: c.system_id.clone(),
                    });
                }

                Ok(client)
            }))
            .await?;

        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: Some(Client::restore(session_keys)),
        })
    }

    /// Dump the current state of the [PseudonymService].
    pub fn dump(
        &self,
    ) -> Result<(EncryptionContexts, SessionKeys, SessionKeySharess), PseudonymServiceError> {
        let session_ids = self.get_current_sessions();
        let session_keys = *self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedClient)?
            .dump();

        let mut session_key_shares = HashMap::new();
        for transcryptor in &self.transcryptors {
            if let Some(key_share) = transcryptor.sks.as_ref() {
                session_key_shares.insert(transcryptor.config.system_id.clone(), *key_share);
            }
        }

        Ok((session_ids?, session_keys, session_key_shares))
    }

    /// Check if the PEP crypto client is initialized.
    pub fn is_initialized(&self) -> bool {
        self.pep_crypto_client.is_some()
    }

    /// Start a new session with all configured transcryptors, and initialize a [Client] using the session keys.
    pub async fn init(&mut self) -> Result<(), PseudonymServiceError> {
        let mut sks = vec![];
        for transcryptor in &mut self.transcryptors {
            let (_session_id, key_share) = transcryptor
                .start_session()
                .await
                .map_err(PseudonymServiceError::TranscryptorError)?;
            sks.push(key_share);
        }

        self.pep_crypto_client = Some(Client::from_shares(self.config.blinded_global_keys, &sks));

        Ok(())
    }

    /// End all sessions
    pub async fn end(&mut self) -> Result<(), PseudonymServiceError> {
        futures::future::try_join_all(self.transcryptors.iter_mut().map(|client| async {
            client
                .end_session()
                .await
                .map_err(PseudonymServiceError::TranscryptorError)
        }))
        .await?;

        Ok(())
    }

    /// Refresh a transcryptor's session
    pub async fn refresh_session(
        &mut self,
        transcryptor_index: usize,
    ) -> Result<(), PseudonymServiceError> {
        let old_sks = self.transcryptors[transcryptor_index].sks;

        let (_, new_sks) = {
            let transcryptor = &mut self.transcryptors[transcryptor_index];
            transcryptor
                .start_session()
                .await
                .map_err(PseudonymServiceError::TranscryptorError)?
        };

        if let (Some(old_sks), Some(crypto_client)) = (old_sks, self.pep_crypto_client.as_mut()) {
            crypto_client.update_session_secret_keys(old_sks, new_sks);
        } else {
            self.init().await?;
        }

        Ok(())
    }

    // TODO add a way to change the order of transcryptors, and add a way to add new transcryptors

    /// Transform an encrypted pseudonym into your own pseudonym.
    pub async fn pseudonymize<T>(
        &mut self,
        encrypted_pseudonym: &T,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<T, PseudonymServiceError>
    where
        T: Pseudonymizable + DeserializeOwned + Serialize + Clone + ApiPath,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted_pseudonym.clone();

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let result = self.transcryptors[i]
                .pseudonymize(
                    &transcrypted,
                    domain_from,
                    domain_to,
                    session_from,
                    &session_id,
                )
                .await;

            transcrypted = match result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    self.transcryptors[i]
                        .pseudonymize(
                            &transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::TranscryptorError(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }

    /// Transform a batch of encrypted pseudonyms into your own pseudonyms.
    /// Notice that the order of the pseudonyms in the input and output vectors are NOT the same, to prevent linking.
    /// If you need to preserve the order, you should call the [pseudonymize] method for each pseudonym individually. (TODO: add a feature flag to preserve order)
    pub async fn pseudonymize_batch<T>(
        &mut self,
        encrypted_pseudonyms: Vec<T>,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<Vec<T>, PseudonymServiceError>
    where
        T: Pseudonymizable + DeserializeOwned + Serialize + Clone + ApiPath + HasStructure,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted_pseudonyms;

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let result = self.transcryptors[i]
                .pseudonymize_batch(
                    transcrypted.clone(),
                    domain_from,
                    domain_to,
                    session_from,
                    &session_id,
                )
                .await;

            transcrypted = match result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    self.transcryptors[i]
                        .pseudonymize_batch(
                            transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::TranscryptorError(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }

    /// Transform an encrypted data point encrypted in one session into a data point you can decrypt.
    pub async fn rekey<T>(
        &mut self,
        encrypted_data_point: &T,
        sessions_from: &EncryptionContexts,
    ) -> Result<T, PseudonymServiceError>
    where
        T: Rekeyable + DeserializeOwned + Serialize + Clone + ApiPath,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted_data_point.clone();

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let result = self.transcryptors[i]
                .rekey(&transcrypted, session_from, &session_id)
                .await;

            transcrypted = match result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    self.transcryptors[i]
                        .rekey(&transcrypted, session_from, &new_session_id)
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::TranscryptorError(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Transform a batch of encrypted data points encrypted in one session into data points you can decrypt.
    /// Notice that the order of the data points in the input and output vectors are NOT the same, to prevent linking.
    /// If you need to preserve the order, you should call the [rekey] method for each data point individually. (TODO: add a feature flag to preserve order)
    pub async fn rekey_batch<T>(
        &mut self,
        encrypted_data_points: Vec<T>,
        sessions_from: &EncryptionContexts,
    ) -> Result<Vec<T>, PseudonymServiceError>
    where
        T: Rekeyable + DeserializeOwned + Serialize + Clone + ApiPath + HasStructure,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted_data_points;

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let result = self.transcryptors[i]
                .rekey_batch(transcrypted.clone(), session_from, &session_id)
                .await;

            transcrypted = match result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    self.transcryptors[i]
                        .rekey_batch(transcrypted, session_from, &new_session_id)
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::TranscryptorError(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Transform a single encrypted data item into data you can decrypt.
    pub async fn transcrypt<T>(
        &mut self,
        encrypted: &T,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<T, PseudonymServiceError>
    where
        T: Transcryptable + DeserializeOwned + Serialize + Clone + ApiPath,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted.clone();

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let result = self.transcryptors[i]
                .transcrypt(
                    &transcrypted,
                    domain_from,
                    domain_to,
                    session_from,
                    &session_id,
                )
                .await;

            transcrypted = match result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    self.transcryptors[i]
                        .transcrypt(
                            &transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::TranscryptorError(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }

    /// Transform a batch of encrypted data for different entities into data you can decrypt.
    /// Notice that the order of the entities in the input and output vectors are NOT the same, to prevent linking.
    pub async fn transcrypt_batch<T>(
        &mut self,
        encrypted: Vec<T>,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<Vec<T>, PseudonymServiceError>
    where
        T: Transcryptable + DeserializeOwned + Serialize + Clone + ApiPath + HasStructure,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted;

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let result = self.transcryptors[i]
                .transcrypt_batch(
                    transcrypted.clone(),
                    domain_from,
                    domain_to,
                    session_from,
                    &session_id,
                )
                .await;

            transcrypted = match result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    self.transcryptors[i]
                        .transcrypt_batch(
                            transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::TranscryptorError(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Encrypt a message using the [Client]'s current session.
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable + 'static>(
        &mut self,
        message: &E,
        rng: &mut R,
    ) -> Result<(E::EncryptedType, EncryptionContexts), PseudonymServiceError>
    where
        SessionKeys: KeyProvider<E::PublicKeyType>,
    {
        let pep_client = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedClient)?;

        Ok((
            pep_client.encrypt(message, rng),
            self.get_current_sessions()?.clone(),
        ))
    }

    /// Batch encrypt a vec of message using the [Client]'s current session.
    pub fn encrypt_batch<R: RngCore + CryptoRng, E: Encryptable + 'static>(
        &mut self,
        message: &[E],
        rng: &mut R,
    ) -> Result<(Vec<E::EncryptedType>, EncryptionContexts), PseudonymServiceError>
    where
        SessionKeys: KeyProvider<E::PublicKeyType>,
    {
        let pep_client = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedClient)?;

        Ok((
            pep_client.encrypt_batch(message, rng)?,
            self.get_current_sessions()?.clone(),
        ))
    }

    pub fn get_current_sessions(&self) -> Result<EncryptionContexts, PseudonymServiceError> {
        let sessions = self
            .transcryptors
            .iter()
            .map(|t| {
                let session_id = t
                    .session_id
                    .clone()
                    .ok_or(PseudonymServiceError::UninitializedTranscryptor)?;

                Ok((t.config.system_id.clone(), session_id))
            })
            .collect::<Result<_, PseudonymServiceError>>()?;

        Ok(EncryptionContexts(sessions))
    }

    /// Decrypt an encrypted message using the [Client]'s current session.
    pub fn decrypt<E: Encrypted>(
        &mut self,
        encrypted: &E,
    ) -> Result<E::UnencryptedType, PseudonymServiceError>
    where
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        let pep_client = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedClient)?;

        Ok(pep_client.decrypt(encrypted))
    }

    /// Batch decrypt a vec of encrypted messages using the [Client]'s current session.
    pub fn decrypt_batch<E: Encrypted>(
        &mut self,
        encrypted: &[E],
    ) -> Result<Vec<E::UnencryptedType>, PseudonymServiceError>
    where
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        let pep_client = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedClient)?;

        Ok(pep_client.decrypt_batch(encrypted)?)
    }
}
