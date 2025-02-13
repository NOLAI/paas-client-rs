mod commands;

use clap::{Arg, Command};
use libpep::high_level::keys::{SessionPublicKey, SessionSecretKey};
use paas_api::status::SystemId;
use paas_client::auth::{BearerTokenAuth, SystemAuths};
use paas_client::pseudonym_service::{PseudonymService, PseudonymServiceConfig};
use paas_client::sessions::EncryptionContexts;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize)]
struct PseudonymServiceDump {
    sessions: EncryptionContexts,
    session_keys: (SessionPublicKey, SessionSecretKey),
}

#[tokio::main]
async fn main() {
    let matches = Command::new("paascli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("config")
                .help("Path to the configuration file")
                .long("config")
                .short('c')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("tokens")
                .help("Path to the file containing auth tokens")
                .long("tokens")
                .short('t')
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

    // Load the configuration and auth tokens
    let config_path = matches
        .get_one::<String>("config")
        .expect("config path is required");
    let config_contents = fs::read_to_string(config_path).expect("Failed to read config file");
    let config: PseudonymServiceConfig =
        serde_json::from_str(&config_contents).expect("Failed to parse config");

    let tokens_path = matches
        .get_one::<String>("tokens")
        .expect("tokens path is required");
    let tokens_contents = fs::read_to_string(tokens_path).expect("Failed to read tokens file");
    let tokens_map: HashMap<SystemId, BearerTokenAuth> =
        serde_json::from_str(&tokens_contents).expect("Failed to parse tokens");
    let auths: SystemAuths = SystemAuths::from_auths(tokens_map);

    // Restore the service from the state dump if it exists
    let state_path = matches.get_one::<String>("state_path");
    let mut service = if let Some(path) = state_path {
        if let Ok(contents) = fs::read_to_string(path) {
            let dump: PseudonymServiceDump =
                serde_json::from_str(&contents).expect("Failed to deserialize service state");
            PseudonymService::restore(config, &auths, dump.sessions, dump.session_keys)
        } else {
            PseudonymService::new(config, &auths)
        }
    } else {
        PseudonymService::new(config, &auths)
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
        let (sessions, session_keys) = service.dump();
        let dump = PseudonymServiceDump {
            sessions,
            session_keys,
        };
        let serialized = serde_json::to_string(&dump).expect("Failed to serialize service dump");
        fs::write(path, serialized).expect("Failed to write state dump to file");
    }
}
