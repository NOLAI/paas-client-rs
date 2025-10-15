use crate::auth::SystemAuths;
use crate::sessions::EncryptionContexts;
use crate::transcryptor_client::{TranscryptorClient, TranscryptorError};
use libpep::distributed::key_blinding::SessionKeyShares;
use libpep::distributed::systems::PEPClient;
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{
    Encryptable, Encrypted, EncryptedAttribute, EncryptedPseudonym, HasSessionKeys,
};
use libpep::high_level::keys::SessionKeys;
use libpep::high_level::ops::EncryptedData;
use paas_api::config::PAASConfig;
use paas_api::status::SystemId;
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum PseudonymServiceError {
    #[error(transparent)]
    TranscryptorError(#[from] TranscryptorError),
    #[error("No auth found for system {0}")]
    MissingAuth(SystemId),
    #[error("No session found for system {0}")]
    MissingSession(SystemId),
    #[error("No session key share found for system {0}")]
    MissingSessionKeyShares(SystemId),
    #[error("PEP crypto client not initialized")]
    UninitializedPEPClient,
    #[error("Transcryptor does not have session")]
    UninitializedTranscryptor,
    #[error("Inconsistent config received from {system}")]
    InconsistentConfig { system: SystemId },
}

#[derive(Clone)]
pub struct PseudonymService {
    pub(crate) config: PAASConfig,
    pub(crate) transcryptors: Vec<TranscryptorClient>,
    pep_crypto_client: Option<PEPClient>,
}

pub type SessionKeySharess = HashMap<SystemId, SessionKeyShares>;

/// Convert encrypted pseudonyms into your own pseudonyms, using the [PseudonymService].
/// The service will communicate with the configured transcryptors, and wraps around a [PEPClient] for cryptographic operations.
impl PseudonymService {
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
            pep_crypto_client: Some(PEPClient::restore(session_keys)),
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
            .ok_or(PseudonymServiceError::UninitializedPEPClient)?
            .dump();

        let mut session_key_shares = HashMap::new();
        for transcryptor in &self.transcryptors {
            if let Some(key_share) = transcryptor.sks.as_ref() {
                session_key_shares.insert(transcryptor.config.system_id.clone(), *key_share);
            }
        }

        Ok((session_ids?, session_keys, session_key_shares))
    }

    /// Start a new session with all configured transcryptors, and initialize a [PEPClient] using the session keys.
    pub async fn init(&mut self) -> Result<(), PseudonymServiceError> {
        let mut sks = vec![];
        for transcryptor in &mut self.transcryptors {
            let (_session_id, key_share) = transcryptor
                .start_session()
                .await
                .map_err(PseudonymServiceError::from)?;
            sks.push(key_share);
        }

        self.pep_crypto_client = Some(PEPClient::new(self.config.blinded_global_keys, &sks));

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
                .map_err(PseudonymServiceError::from)?
        };

        if old_sks.is_some() && self.pep_crypto_client.is_some() {
            if let Some(crypto_client) = self.pep_crypto_client.as_mut() {
                crypto_client.update_session_secret_keys(old_sks.unwrap(), new_sks);
            }
        } else {
            self.init().await?;
        }

        Ok(())
    }

    /// Transform an encrypted pseudonym into your own pseudonym.
    pub async fn pseudonymize(
        &mut self,
        encrypted_pseudonym: &EncryptedPseudonym,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<EncryptedPseudonym, PseudonymServiceError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = *encrypted_pseudonym;

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let transcryption_result = self.transcryptors[i]
                .pseudonymize(
                    &transcrypted,
                    domain_from,
                    domain_to,
                    session_from,
                    &session_id,
                )
                .await;

            transcrypted = match transcryption_result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let transcryptor = &self.transcryptors[i];
                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    transcryptor
                        .pseudonymize(
                            &transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::from(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }

    // TODO add a way to change the order of transcryptors, and add a way to add new transcryptors

    /// Transform a batch of encrypted pseudonyms into your own pseudonyms.
    /// Notice that the order of the pseudonyms in the input and output vectors are NOT the same, to prevent linking.
    /// If you need to preserve the order, you should call the [pseudonymize] method for each pseudonym individually. (TODO: add a feature flag to preserve order)
    pub async fn pseudonymize_batch(
        &mut self,
        encrypted_pseudonyms: &[EncryptedPseudonym],
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<Vec<EncryptedPseudonym>, PseudonymServiceError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted_pseudonyms.to_owned();

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let transcryption_result = {
                let transcryptor = &self.transcryptors[i];
                transcryptor
                    .pseudonymize_batch(
                        &transcrypted,
                        domain_from,
                        domain_to,
                        session_from,
                        &session_id,
                    )
                    .await
            };

            transcrypted = match transcryption_result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let transcryptor = &self.transcryptors[i];
                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    transcryptor
                        .pseudonymize_batch(
                            &transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::from(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Transform an encrypted data point encrypted in one session into a data point you can decrypt.
    pub async fn rekey(
        &mut self,
        encrypted_data_point: &EncryptedAttribute,
        sessions_from: &EncryptionContexts,
    ) -> Result<EncryptedAttribute, PseudonymServiceError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = *encrypted_data_point;

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let rekey_result = {
                let transcryptor = &self.transcryptors[i];
                transcryptor
                    .rekey(&transcrypted, session_from, &session_id)
                    .await
            };

            transcrypted = match rekey_result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let transcryptor = &self.transcryptors[i];
                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    transcryptor
                        .rekey(&transcrypted, session_from, &new_session_id)
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::from(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Transform a batch of encrypted data points encrypted in one session into into data points you can decrypt.
    /// Notice that the order of the data points in the input and output vectors are NOT the same, to prevent linking.
    /// If you need to preserve the order, you should call the [rekey] method for each data points individually. (TODO: add a feature flag to preserve order)
    pub async fn rekey_batch(
        &mut self,
        encrypted_data_points: &[EncryptedAttribute],
        sessions_from: &EncryptionContexts,
    ) -> Result<Vec<EncryptedAttribute>, PseudonymServiceError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted_data_points.to_owned();

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let rekey_result = {
                let transcryptor = &self.transcryptors[i];
                transcryptor
                    .rekey_batch(&transcrypted, session_from, &session_id)
                    .await
            };

            transcrypted = match rekey_result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let transcryptor = &self.transcryptors[i];
                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    transcryptor
                        .rekey_batch(&transcrypted, session_from, &new_session_id)
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::from(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Transform a batch of encrypted data for different entities into data you can decrypt
    /// Notice that the order of the entities in the input and output vectors are NOT the same, to prevent linking.
    pub async fn transcrypt(
        &mut self,
        encrypted: &[EncryptedData],
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<Vec<EncryptedData>, PseudonymServiceError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let mut transcrypted = encrypted.to_owned();

        for i in 0..self.transcryptors.len() {
            let system_id = &self.transcryptors[i].config.system_id;
            let session_from = sessions_from
                .get(system_id)
                .ok_or_else(|| PseudonymServiceError::MissingSession(system_id.clone()))?;

            let session_id = match &self.transcryptors[i].session_id {
                Some(id) => id.clone(),
                None => return Err(PseudonymServiceError::UninitializedTranscryptor),
            };

            let transcryption_result = {
                let transcryptor = &self.transcryptors[i];
                transcryptor
                    .transcrypt(
                        &transcrypted,
                        domain_from,
                        domain_to,
                        session_from,
                        &session_id,
                    )
                    .await
            };

            transcrypted = match transcryption_result {
                Err(TranscryptorError::InvalidSession(_)) => {
                    self.refresh_session(i).await?;

                    let transcryptor = &self.transcryptors[i];
                    let new_session_id = match &self.transcryptors[i].session_id {
                        Some(id) => id.clone(),
                        None => return Err(PseudonymServiceError::UninitializedTranscryptor),
                    };
                    transcryptor
                        .transcrypt(
                            &transcrypted,
                            domain_from,
                            domain_to,
                            session_from,
                            &new_session_id,
                        )
                        .await?
                }
                Err(err) => return Err(PseudonymServiceError::from(err)),
                Ok(value) => value,
            };
        }

        Ok(transcrypted)
    }
    /// Encrypt a message using the [PEPClient]'s current session.
    pub async fn encrypt<R: RngCore + CryptoRng, E: Encryptable + HasSessionKeys + 'static>(
        &mut self,
        message: &E,
        rng: &mut R,
    ) -> Result<(E::EncryptedType, EncryptionContexts), PseudonymServiceError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let pep_client = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedPEPClient)?;

        Ok((
            pep_client.encrypt(message, rng),
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

    /// Decrypt an encrypted message using the [PEPClient]'s current session.
    pub async fn decrypt<E: Encrypted>(
        &mut self,
        encrypted: &E,
    ) -> Result<E::UnencryptedType, PseudonymServiceError>
    where
        E::UnencryptedType: HasSessionKeys + 'static,
    {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }

        let pep_client = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedPEPClient)?;

        Ok(pep_client.decrypt(encrypted))
    }
}
