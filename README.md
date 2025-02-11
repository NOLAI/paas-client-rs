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
let config = PseudonymServiceConfig {
    blinded_global_secret_key: BlindedGlobalSecretKey::decode_from_hex("dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908").unwrap(), 
    global_public_key: GlobalPublicKey::from_hex("3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62").unwrap(),
    transcryptors: vec![
        TranscryptorConfig {
            system_id: "test_system_1".to_string(),
            url: "http://localhost:8080",
        },
        TranscryptorConfig {
            system_id: "test_system_2".to_string(),
            url: "http://localhost:8081",
        },
    ],
};

let auth_tokens = AuthTokens(HashMap::from([
    ("test_system_1".to_string(), "test_token_1".to_string()),
    ("test_system_2".to_string(), "test_token_2".to_string()),
]));

let mut service = PseudonymService::new(config, auth_tokens);

let encrypted_pseudonym = EncryptedPseudonym::from_base64("nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==").unwrap();
let sessions = EncryptionContexts(HashMap::from([
    ("test_system_1".to_string(), EncryptionContext::from("session_1")),
    ("test_system_2".to_string(), EncryptionContext::from("session_2")),
]));

let domain_from = PseudonymizationDomain::from("domain1");
let domain_to = PseudonymizationDomain::from("domain2");

let mut service = PseudonymService::new(config, auth_tokens);
let result = service.pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to).await;
let pseudonym = service.decrypt(result).await;
```
