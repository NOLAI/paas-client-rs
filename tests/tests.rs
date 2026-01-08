use chrono::Utc;
use paas_api::config::{PAASConfig, TranscryptorConfig};
use paas_api::status::{StatusResponse, VersionInfo};
use paas_client::auth::{BearerTokenAuth, SystemAuths};
use paas_client::pseudonym_service::PseudonymService;
use paas_client::sessions::EncryptionContexts;
use std::collections::HashMap;
use libpep::core::data::{Encrypted, EncryptedPseudonym};
use libpep::core::keys::{AttributeGlobalPublicKey, GlobalPublicKeys, PseudonymGlobalPublicKey, PublicKey};
use libpep::core::transcryption::{EncryptionContext, PseudonymizationDomain};
use libpep::distributed::server::setup::{BlindedAttributeGlobalSecretKey, BlindedGlobalKeys, BlindedPseudonymGlobalSecretKey};

#[tokio::test]
async fn test_create_pep_client() {
    let mut server = mockito::Server::new_async().await;

    let config = PAASConfig {
        blinded_global_keys: BlindedGlobalKeys {
            pseudonym: BlindedPseudonymGlobalSecretKey::from_hex(
                "dbf0d6e82ea1147350c1c613ba4ef160e35f3572c681b62f6f01e4606a5f0b06",
            )
            .unwrap(),
            attribute: BlindedAttributeGlobalSecretKey::from_hex(
                "00f1c8be6e2f12c052d2d4ca5fb0fe216a304fb7b218a064f0560ff39359b809",
            )
            .unwrap(),
        },
        global_public_keys: GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey::from_hex(
                "b408b8dcf99dcf1f9b93692abc66b89bf1869bdd1a24d594d6dea66c5a840262",
            )
            .unwrap(),
            attribute: AttributeGlobalPublicKey::from_hex(
                "301102f578ed8ffa6155828db658615c14e488aebf34efb24076ee5ccf1daf2e",
            )
            .unwrap(),
        },
        transcryptors: vec![
            TranscryptorConfig {
                system_id: "test_system_1".to_string(),
                url: server.url().parse().unwrap(),
            },
            TranscryptorConfig {
                system_id: "test_system_2".to_string(),
                url: server.url().parse().unwrap(),
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
        .with_body(r#"{"session_id": "test_session", "session_key_shares": {"pseudonym": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a", "attribute": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a"}}"#)
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
    let mut service = PseudonymService::new_allow_http(config, auths)
        .await
        .expect("Failed to create service");
    service.init().await.expect("Failed to init service");
    // assert!(service.pep_crypto_client.is_some());
}

#[tokio::test]
async fn test_pseudonymize() {
    let mut server = mockito::Server::new_async().await;

    let config = PAASConfig {
        blinded_global_keys: BlindedGlobalKeys {
            pseudonym: BlindedPseudonymGlobalSecretKey::from_hex(
                "dbf0d6e82ea1147350c1c613ba4ef160e35f3572c681b62f6f01e4606a5f0b06",
            )
            .unwrap(),
            attribute: BlindedAttributeGlobalSecretKey::from_hex(
                "00f1c8be6e2f12c052d2d4ca5fb0fe216a304fb7b218a064f0560ff39359b809",
            )
            .unwrap(),
        },
        global_public_keys: GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey::from_hex(
                "b408b8dcf99dcf1f9b93692abc66b89bf1869bdd1a24d594d6dea66c5a840262",
            )
            .unwrap(),
            attribute: AttributeGlobalPublicKey::from_hex(
                "301102f578ed8ffa6155828db658615c14e488aebf34efb24076ee5ccf1daf2e",
            )
            .unwrap(),
        },
        transcryptors: vec![
            TranscryptorConfig {
                system_id: "test_system_1".to_string(),
                url: server.url().parse().unwrap(),
            },
            TranscryptorConfig {
                system_id: "test_system_2".to_string(),
                url: server.url().parse().unwrap(),
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
        .with_body(r#"{"session_id": "test_session", "session_key_shares": {"pseudonym": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a", "attribute": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a"}}"#)
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

    let mut service = PseudonymService::new_allow_http(config, auths)
        .await
        .expect("Failed to create service");
    let result = service
        .pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to)
        .await
        .expect("Failed to pseudonymize");
    // We dont test the actual result, just check with the content of the mock response
    assert_eq!(result, EncryptedPseudonym::from_base64("gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==").unwrap());
}
