mod auth;
mod commands;
mod oidc_auth;

use crate::auth::ensure_authenticated;
use clap::{Arg, Command};
use libpep::high_level::keys::{SessionPublicKey, SessionSecretKey};
use paas_api::config::PAASConfig;
use paas_client::auth::{BearerTokenAuth, SystemAuths};
use paas_client::pseudonym_service::{PseudonymService, SessionKeyShares};
use paas_client::sessions::EncryptionContexts;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize)]
struct PseudonymServiceDump {
    sessions: EncryptionContexts,
    session_keys: (SessionPublicKey, SessionSecretKey),
    session_key_shares: SessionKeyShares,
}
async fn load_config(config_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    if config_path.starts_with("http://") || config_path.starts_with("https://") {
        let response = reqwest::get(config_path).await?;
        Ok(response.text().await?)
    } else {
        // Load config from local file
        Ok(fs::read_to_string(config_path)?)
    }
}

#[tokio::main]
async fn main() {
    let matches = Command::new("paascli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("config")
                .help("Path to the configuration file or trusted URL to download from")
                .long("config")
                .short('c')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("auth_store")
                .help("Path to the authentication store file")
                .long("auth-store")
                .short('a')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("oidc_config")
                .help("Path to OIDC configuration file")
                .long("oidc-config")
                .short('o')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("state_path")
                .help("Path to restore state from and dump state to")
                .long("state")
                .short('s')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .subcommand(commands::pseudonymize::command())
        .subcommand(commands::encrypt::command())
        .get_matches();

    let config_path = matches
        .get_one::<String>("config")
        .expect("config path is required");

    let auth_store_path = matches
        .get_one::<String>("auth_store")
        .expect("auth store path is required");

    let oidc_config_path = matches
        .get_one::<String>("oidc_config")
        .expect("oidc config path is required");

    let config_contents = load_config(config_path)
        .await
        .expect("Failed to load config file");

    let config: PAASConfig =
        serde_json::from_str(&config_contents).expect("Failed to parse config");

    let mut tokens_map = HashMap::new();
    for config in config.transcryptors.clone() {
        let access_token = match ensure_authenticated(
            auth_store_path,
            oidc_config_path,
            &config.system_id,
        )
        .await
        {
            Ok(token) => token,
            Err(e) => {
                eprintln!("Authentication failed: {}", e);
                std::process::exit(1);
            }
        };
        tokens_map.insert(config.system_id.clone(), BearerTokenAuth::new(access_token));
    }
    let auths = SystemAuths::from_auths(tokens_map);

    // Restore the service from the state dump if it exists
    let state_path = matches.get_one::<String>("state_path");
    let mut service = if let Some(path) = state_path {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let dump: PseudonymServiceDump = serde_json::from_str(&contents)
                    .expect("Failed to deserialize service state from file");

                PseudonymService::restore(
                    config,
                    auths,
                    dump.sessions,
                    dump.session_key_shares,
                    dump.session_keys,
                )
                .await
                .expect("Failed to restore service from state")
            }
            Err(e) => {
                eprintln!("Failed to read state file: {}, creating new service", e);
                PseudonymService::new(config, auths)
                    .await
                    .expect("Failed to create new service")
            }
        }
    } else {
        PseudonymService::new(config, auths)
            .await
            .expect("Failed to create new service")
    };

    // Execute the subcommand
    match matches.subcommand() {
        Some(("pseudonymize", matches)) => {
            commands::pseudonymize::execute(matches, &mut service).await;
        }
        Some(("encrypt", matches)) => {
            commands::encrypt::execute(matches, &mut service).await;
        }
        _ => {
            println!("No command specified. Use --help for usage information.");
        }
    }

    // Write the state dump to the file
    if let Some(path) = state_path {
        let (sessions, session_keys, session_key_shares) =
            service.dump().expect("Failed to dump state");
        let dump = PseudonymServiceDump {
            sessions,
            session_keys,
            session_key_shares,
        };
        let serialized = serde_json::to_string(&dump).expect("Failed to serialize service dump");
        fs::write(path, serialized).expect("Failed to write state dump to file");
    }
}
