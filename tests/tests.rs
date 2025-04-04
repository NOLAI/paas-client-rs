use chrono::Utc;
use libpep::distributed::key_blinding::{BlindedGlobalSecretKey, SafeScalar};
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{GlobalPublicKey, PublicKey};
use paas_api::config::{PAASConfig, TranscryptorConfig};
use paas_api::status::{StatusResponse, VersionInfo};
use paas_client::auth::{BearerTokenAuth, SystemAuths};
use paas_client::pseudonym_service::PseudonymService;
use paas_client::sessions::EncryptionContexts;
use std::collections::HashMap;

#[tokio::test]
async fn test_create_pep_client() {
    let mut server = mockito::Server::new_async().await;

    let config = PAASConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::decode_from_hex(
            "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908",
        )
        .unwrap(),
        global_public_key: GlobalPublicKey::from_hex(
            "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62",
        )
        .unwrap(),
        transcryptors: vec![
            TranscryptorConfig {
                system_id: "test_system_1".to_string(),
                url: server.url(),
            },
            TranscryptorConfig {
                system_id: "test_system_2".to_string(),
                url: server.url(),
            },
        ],
    };

    let mock_status1 = StatusResponse {
        system_id: "test_system_1".to_string(),
        timestamp: Utc::now(),
        version_info: VersionInfo::default(),
    };
    let mock_status2 = StatusResponse {
        system_id: "test_system_2".to_string(),
        timestamp: Utc::now(),
        version_info: VersionInfo::default(),
    };
    let _status1 = server
        .mock("GET", "/status")
        .with_status(200)
        .with_body(serde_json::to_string(&mock_status1).unwrap())
        .create();
    let _status2 = server
        .mock("GET", "/status")
        .with_status(200)
        .with_body(serde_json::to_string(&mock_status2).unwrap())
        .create();

    let _config = server
        .mock("GET", "/config")
        .with_status(200)
        .with_body(serde_json::to_string(&config).unwrap())
        .create();

    let _start = server.mock("POST", "/sessions/start")
        .with_status(200)
        .with_body(r#"{"session_id": "test_session", "key_share": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a"}"#)
        .create();

    let auths = SystemAuths::from_auths(HashMap::from([
        (
            "test_system_1".to_string(),
            BearerTokenAuth::new("test_token_1".to_string()),
        ),
        (
            "test_system_2".to_string(),
            BearerTokenAuth::new("test_token_2".to_string()),
        ),
    ]));
    let mut service = PseudonymService::new(config, auths)
        .await
        .expect("Failed to create service");
    service.init().await.expect("Failed to init service");
    // assert!(service.pep_crypto_client.is_some());
}

#[tokio::test]
async fn test_pseudonymize() {
    let mut server = mockito::Server::new_async().await;

    let config = PAASConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::decode_from_hex(
            "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908",
        )
        .unwrap(),
        global_public_key: GlobalPublicKey::from_hex(
            "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62",
        )
        .unwrap(),
        transcryptors: vec![
            TranscryptorConfig {
                system_id: "test_system_1".to_string(),
                url: server.url(),
            },
            TranscryptorConfig {
                system_id: "test_system_2".to_string(),
                url: server.url(),
            },
        ],
    };

    let mock_status1 = StatusResponse {
        system_id: "test_system_1".to_string(),
        timestamp: Utc::now(),
        version_info: VersionInfo::default(),
    };
    let mock_status2 = StatusResponse {
        system_id: "test_system_2".to_string(),
        timestamp: Utc::now(),
        version_info: VersionInfo::default(),
    };
    let _status1 = server
        .mock("GET", "/status")
        .with_status(200)
        .with_body(serde_json::to_string(&mock_status1).unwrap())
        .create();
    let _status2 = server
        .mock("GET", "/status")
        .with_status(200)
        .with_body(serde_json::to_string(&mock_status2).unwrap())
        .create();

    let _config = server
        .mock("GET", "/config")
        .with_status(200)
        .with_body(serde_json::to_string(&config).unwrap())
        .create();

    let _start = server.mock("POST", "/sessions/start")
        .with_status(200)
        .with_body(r#"{"session_id": "test_session", "key_share": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a"}"#)
        .create();

    let _pseudonymize = server.mock("POST", "/pseudonymize")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(r#"{"encrypted_pseudonym": "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA=="}"#)
        .create();

    let auths = SystemAuths::from_auths(HashMap::from([
        (
            "test_system_1".to_string(),
            BearerTokenAuth::new("test_token_1".to_string()),
        ),
        (
            "test_system_2".to_string(),
            BearerTokenAuth::new("test_token_2".to_string()),
        ),
    ]));

    let encrypted_pseudonym = EncryptedPseudonym::from_base64(
        "nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==",
    )
    .unwrap();
    let sessions = EncryptionContexts(HashMap::from([
        (
            "test_system_1".to_string(),
            EncryptionContext::from("session_1"),
        ),
        (
            "test_system_2".to_string(),
            EncryptionContext::from("session_2"),
        ),
    ]));

    let domain_from = PseudonymizationDomain::from("domain1");
    let domain_to = PseudonymizationDomain::from("domain2");

    let mut service = PseudonymService::new(config, auths)
        .await
        .expect("Failed to create service");
    let result = service
        .pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to)
        .await
        .expect("Failed to pseudonymize");
    // We dont test the actual result, just check with the content of the mock response
    assert_eq!(result, EncryptedPseudonym::from_base64("gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==").unwrap());
}
