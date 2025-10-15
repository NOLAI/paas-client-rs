# PAAS client (rust)
[![Crates.io](https://img.shields.io/crates/v/paas-client.svg)](https://crates.io/crates/paas-client)
[![Downloads](https://img.shields.io/crates/d/paas-client.svg)](https://crates.io/crates/paas-client)
[![License](https://img.shields.io/crates/l/paas-client.svg)](https://crates.io/crates/paas-client)
[![Documentation](https://docs.rs/paas-client/badge.svg)](https://docs.rs/paas-client)
[![Dependencies](https://deps.rs/repo/github/NOLAI/paas-client-rs/status.svg)](https://deps.rs/repo/github/NOLAI/paas-client-rs)

This project contains the Rust client implementation for PAAS, the PEP Authorisation API Service (or _Pseudonymization as a Service_).
It implements interaction with multiple [PAAS servers](https://github.com/NOLAI/paas-server) using the [PAAS API](https://github.com/NOLAI/paas-api).

PAAS forms a REST API around [`libpep`](https://github.com/NOLAI/libpep) for homomorphic pseudonymization.
Using multiple PAAS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.

Each transcryptor is able to enforce access control policies, such as only allowing pseudonymization for certain domains or contexts.
This way, using PAAS, you can enforce central monitoring and control over unlinkable data processing in different domains or contexts.

## Installation
Install with
```bash
cargo install paas-client
```

In addition to the library, a binary `paascli` is available to interact with the PAAS server.
For example run the following command to pseudonymize an encrypted pseudonym from domain1 to domain2:
```bash
paascli --config config.json --tokens tokens.json --state state.json pseudonymize CvkMpV4E98A1kWReUi0dE4mGRm1ToAj_D5-FrSi1FBqCrqE6d5HNrV8JW6vsGkwputG2S821sfjzjsyFGUPzAg== eyJQYWFTLWRlbW8tMyI6InVzZXIxXzB4T0VpZXBPTjAiLCJQYWFTLWRlbW8tMSI6InVzZXIxXzhGZmhDQU5WVmIiLCJQYWFTLWRlbW8tMiI6InVzZXIxX2tibk5UUVZpYjkifQ== domain1 domain2
```

Or during development, you can run:
```bash
cargo run --bin paascli -- --config config.json --tokens tokens.json --state state.json pseudonymize CvkMpV4E98A1kWReUi0dE4mGRm1ToAj_D5-FrSi1FBqCrqE6d5HNrV8JW6vsGkwputG2S821sfjzjsyFGUPzAg== eyJQYWFTLWRlbW8tMyI6InVzZXIxXzB4T0VpZXBPTjAiLCJQYWFTLWRlbW8tMSI6InVzZXIxXzhGZmhDQU5WVmIiLCJQYWFTLWRlbW8tMiI6InVzZXIxX2tibk5UUVZpYjkifQ== domain1 domain2
```

## Usage
```rust
use libpep::distributed::key_blinding::{BlindedGlobalKeys, BlindedPseudonymGlobalSecretKey, BlindedAttributeGlobalSecretKey};
use libpep::high_level::keys::{GlobalPublicKeys, PseudonymGlobalPublicKey, AttributeGlobalPublicKey};
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::EncryptedPseudonym;
use paas_api::config::{PAASConfig, TranscryptorConfig};
use paas_client::auth::{BearerTokenAuth, SystemAuths};
use paas_client::pseudonym_service::PseudonymService;
use paas_client::sessions::EncryptionContexts;
use std::collections::HashMap;

let config = PAASConfig {
    blinded_global_keys: BlindedGlobalKeys {
        pseudonym: BlindedPseudonymGlobalSecretKey::decode_from_hex(
            "dbf0d6e82ea1147350c1c613ba4ef160e35f3572c681b62f6f01e4606a5f0b06"
        ).unwrap(),
        attribute: BlindedAttributeGlobalSecretKey::decode_from_hex(
            "00f1c8be6e2f12c052d2d4ca5fb0fe216a304fb7b218a064f0560ff39359b809"
        ).unwrap(),
    },
    global_public_key: GlobalPublicKeys {
        pseudonym: PseudonymGlobalPublicKey::from_hex(
            "b408b8dcf99dcf1f9b93692abc66b89bf1869bdd1a24d594d6dea66c5a840262"
        ).unwrap(),
        attribute: AttributeGlobalPublicKey::from_hex(
            "301102f578ed8ffa6155828db658615c14e488aebf34efb24076ee5ccf1daf2e"
        ).unwrap(),
    },
    transcryptors: vec![
        TranscryptorConfig {
            system_id: "test_system_1".to_string(),
            url: "http://localhost:8080".to_string(),
        },
        TranscryptorConfig {
            system_id: "test_system_2".to_string(),
            url: "http://localhost:8081".to_string(),
        },
    ],
};

let auths = SystemAuths::from_auths(HashMap::from([
    ("test_system_1".to_string(), BearerTokenAuth::new("test_token_1".to_string())),
    ("test_system_2".to_string(), BearerTokenAuth::new("test_token_2".to_string())),
]));

let encrypted_pseudonym = EncryptedPseudonym::from_base64(
    "nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw=="
).unwrap();
let sessions = EncryptionContexts(HashMap::from([
    ("test_system_1".to_string(), EncryptionContext::from("session_1")),
    ("test_system_2".to_string(), EncryptionContext::from("session_2")),
]));

let domain_from = PseudonymizationDomain::from("domain1");
let domain_to = PseudonymizationDomain::from("domain2");

let mut service = PseudonymService::new(config, auths).await.expect("Failed to create service");
let result = service.pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to).await.expect("Failed to pseudonymize");
let pseudonym = service.decrypt(&result).await.expect("Failed to decrypt");
```
