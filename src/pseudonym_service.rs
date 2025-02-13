use crate::auth::SystemAuths;
use crate::sessions::EncryptionContexts;
use crate::transcryptor_client::{TranscryptorClient, TranscryptorConfig, TranscryptorError};
use libpep::distributed::key_blinding::BlindedGlobalSecretKey;
use libpep::distributed::systems::PEPClient;
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{Encryptable, Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{GlobalPublicKey, SessionPublicKey, SessionSecretKey};
use paas_api::status::SystemId;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymServiceConfig {
    pub blinded_global_secret_key: BlindedGlobalSecretKey,
    pub global_public_key: GlobalPublicKey,
    pub transcryptors: Vec<TranscryptorConfig>,
} // TODO servers should host these configs in a well-known location

#[derive(Clone)]
pub struct PseudonymService {
    // Now only needs lifetime param, no generic A
    config: PseudonymServiceConfig,
    transcryptors: Vec<TranscryptorClient>,
    pub pep_crypto_client: Option<PEPClient>, // TODO make this private
}

#[derive(Debug, thiserror::Error)]
pub enum PseudonymServiceError {
    #[error(transparent)]
    TranscryptorError(#[from] TranscryptorError),
    #[error("No auth found for system {0}")]
    MissingAuth(SystemId),
    #[error("No session found for system {0}")]
    MissingSession(SystemId),
    #[error("PEP crypto client not initialized")]
    UninitializedPEPClient,
    #[error("Transcryptor does not have session")]
    UninitializedTranscryptor,
}

/// Convert encrypted pseudonyms into your own pseudonyms, using the [PseudonymService].
/// The service will communicate with the configured transcryptors, and wraps around a [PEPClient] for cryptographic operations.
impl PseudonymService {
    pub fn new(
        config: PseudonymServiceConfig,
        auths: SystemAuths, // Take ownership of SystemAuths
    ) -> Result<Self, PseudonymServiceError> {
        let transcryptors = config
            .transcryptors
            .iter()
            .map(|c| {
                auths
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingAuth(c.system_id.clone()))
                    .map(|auth| TranscryptorClient::new(c.clone(), auth))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: None,
        })
    }

    /// Restore a [PseudonymService] from a dumped state.
    pub fn restore(
        config: PseudonymServiceConfig,
        auths: SystemAuths,
        session_ids: EncryptionContexts,
        session_keys: (SessionPublicKey, SessionSecretKey),
    ) -> Result<Self, PseudonymServiceError> {
        let transcryptors = config
            .transcryptors
            .iter()
            .map(|c| {
                let auth = auths
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingAuth(c.system_id.clone()))?;

                let session_id = session_ids
                    .get(&c.system_id)
                    .ok_or_else(|| PseudonymServiceError::MissingSession(c.system_id.clone()))?;

                Ok(TranscryptorClient::restore(
                    c.clone(),
                    auth,
                    session_id.clone(),
                ))
            })
            .collect::<Result<Vec<_>, PseudonymServiceError>>()?;

        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: Some(PEPClient::restore(session_keys.0, session_keys.1)),
        })
    }

    /// Dump the current state of the [PseudonymService].
    pub fn dump(
        &self,
    ) -> Result<(EncryptionContexts, (SessionPublicKey, SessionSecretKey)), PseudonymServiceError>
    {
        let session_ids = self.get_current_sessions();
        let session_keys = self
            .pep_crypto_client
            .as_ref()
            .ok_or(PseudonymServiceError::UninitializedPEPClient)?
            .dump();

        Ok((session_ids?, session_keys))
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

        self.pep_crypto_client = Some(PEPClient::new(self.config.blinded_global_secret_key, &sks));

        Ok(())
    }

    // TODO: add a way to check if the session is still valid, and add a way to refresh the session

    // TODO: end the session

    // TODO: check status, and check if system id is correct

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
        for transcryptor in &self.transcryptors {
            let session_from = sessions_from
                .get(&transcryptor.config.system_id)
                .ok_or_else(|| {
                    PseudonymServiceError::MissingSession(transcryptor.config.system_id.clone())
                })?;

            let session_id = transcryptor
                .session_id
                .as_ref()
                .ok_or(PseudonymServiceError::UninitializedTranscryptor)?;

            transcrypted = transcryptor
                .pseudonymize(
                    &transcrypted,
                    domain_from,
                    domain_to,
                    session_from,
                    session_id,
                )
                .await
                .map_err(PseudonymServiceError::from)?;
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
        for transcryptor in &self.transcryptors {
            let session_from = sessions_from
                .get(&transcryptor.config.system_id)
                .ok_or_else(|| {
                    PseudonymServiceError::MissingSession(transcryptor.config.system_id.clone())
                })?;

            let session_id = transcryptor
                .session_id
                .as_ref()
                .ok_or(PseudonymServiceError::UninitializedTranscryptor)?;

            transcrypted = transcryptor
                .pseudonymize_batch(
                    transcrypted,
                    domain_from,
                    domain_to,
                    session_from,
                    session_id,
                )
                .await
                .map_err(PseudonymServiceError::from)?;
        }

        Ok(transcrypted)
    }

    // TODO add rekey methods

    /// Encrypt a message using the [PEPClient]'s current session.
    pub async fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
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
    ) -> Result<E::UnencryptedType, PseudonymServiceError> {
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
