use crate::auth::SystemAuths;
use crate::sessions::EncryptionContexts;
use crate::transcryptor_client::{TranscryptorClient, TranscryptorConfig};
use libpep::distributed::key_blinding::BlindedGlobalSecretKey;
use libpep::distributed::systems::PEPClient;
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{Encryptable, Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{GlobalPublicKey, SessionPublicKey, SessionSecretKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymServiceConfig {
    pub blinded_global_secret_key: BlindedGlobalSecretKey,
    pub global_public_key: GlobalPublicKey,
    pub transcryptors: Vec<TranscryptorConfig>,
} // TODO servers should host these configs in a well-known location

#[derive(Clone)]
pub struct PseudonymService<'a> {
    // Now only needs lifetime param, no generic A
    config: PseudonymServiceConfig,
    transcryptors: Vec<TranscryptorClient<'a>>,
    pub pep_crypto_client: Option<PEPClient>, // TODO make this private
}

/// Convert encrypted pseudonyms into your own pseudonyms, using the [PseudonymService].
/// The service will communicate with the configured transcryptors, and wraps around a [PEPClient] for cryptographic operations.
impl<'a> PseudonymService<'a> {
    pub fn new(config: PseudonymServiceConfig, auths: &'a SystemAuths) -> Self {
        let transcryptors = config
            .transcryptors
            .iter()
            .map(|c| {
                TranscryptorClient::new(
                    c.clone(),
                    auths.get(&c.system_id).expect("No auth found for system"),
                )
            })
            .collect();
        Self {
            config,
            transcryptors,
            pep_crypto_client: None,
        }
    }

    /// Restore a [PseudonymService] from a dumped state.
    pub fn restore(
        config: PseudonymServiceConfig,
        auths: &'a SystemAuths,
        session_ids: EncryptionContexts,
        session_keys: (SessionPublicKey, SessionSecretKey),
    ) -> Self {
        let transcryptors = config
            .transcryptors
            .iter()
            .map(|c| {
                TranscryptorClient::restore(
                    c.clone(),
                    auths.get(&c.system_id).expect("No auth found for system"),
                    session_ids
                        .get(&c.system_id)
                        .expect("No session id found for system")
                        .clone(),
                )
            })
            .collect();
        Self {
            config,
            transcryptors,
            pep_crypto_client: Some(PEPClient::restore(session_keys.0, session_keys.1)),
        }
    }

    /// Dump the current state of the [PseudonymService].
    pub fn dump(&self) -> (EncryptionContexts, (SessionPublicKey, SessionSecretKey)) {
        let session_ids = self.get_current_sessions();
        let session_keys = self.pep_crypto_client.as_ref().unwrap().dump();
        (session_ids, session_keys)
    }

    /// Start a new session with all configured transcryptors, and initialize a [PEPClient] using the session keys.
    pub async fn init(&mut self) {
        let mut sks = vec![];
        for transcryptor in &mut self.transcryptors {
            let (_session_id, key_share) = transcryptor.start_session().await.unwrap();
            sks.push(key_share);
        }
        self.pep_crypto_client = Some(PEPClient::new(self.config.blinded_global_secret_key, &sks));
    } // TODO: add a way to check if the session is still valid, and add a way to refresh the session

    // TODO: end the session

    // TODO: check status, and check if system id is correct

    /// Transform an encrypted pseudonym into your own pseudonym.
    pub async fn pseudonymize(
        &mut self,
        encrypted_pseudonym: &EncryptedPseudonym,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> EncryptedPseudonym {
        if self.pep_crypto_client.is_none() {
            self.init().await;
        }
        let mut transcrypted = *encrypted_pseudonym;
        for transcryptor in &self.transcryptors {
            transcrypted = transcryptor
                .pseudonymize(
                    &transcrypted,
                    domain_from,
                    domain_to,
                    sessions_from.get(&transcryptor.config.system_id).unwrap(),
                    transcryptor.session_id.as_ref().unwrap(),
                )
                .await
                .expect("Communication with transcryptor failed");
        }
        transcrypted
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
    ) -> Vec<EncryptedPseudonym> {
        if self.pep_crypto_client.is_none() {
            self.init().await;
        }
        let mut transcrypted = encrypted_pseudonyms.to_owned();
        for transcryptor in &self.transcryptors {
            transcrypted = transcryptor
                .pseudonymize_batch(
                    transcrypted,
                    domain_from,
                    domain_to,
                    sessions_from.get(&transcryptor.config.system_id).unwrap(),
                    transcryptor.session_id.as_ref().unwrap(),
                )
                .await
                .expect("Communication with transcryptor failed");
        }
        transcrypted
    }

    // TODO add transcypt_batch method

    /// Encrypt a message using the [PEPClient]'s current session.
    pub async fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &mut self,
        message: &E,
        rng: &mut R,
    ) -> (E::EncryptedType, EncryptionContexts) {
        if self.pep_crypto_client.is_none() {
            self.init().await;
        }
        (
            self.pep_crypto_client
                .as_ref()
                .unwrap()
                .encrypt(message, rng),
            self.get_current_sessions().clone(),
        )
    }

    pub fn get_current_sessions(&self) -> EncryptionContexts {
        let sessions = self
            .transcryptors
            .iter()
            .map(|t| (t.config.system_id.clone(), t.session_id.clone().unwrap()))
            .collect();
        EncryptionContexts(sessions)
    }

    /// Decrypt an encrypted message using the [PEPClient]'s current session.
    pub async fn decrypt<E: Encrypted>(&mut self, encrypted: &E) -> E::UnencryptedType {
        if self.pep_crypto_client.is_none() {
            self.init().await;
        }
        self.pep_crypto_client.as_ref().unwrap().decrypt(encrypted)
    }
}
