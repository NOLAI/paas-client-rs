use clap::{Arg, Command};
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use paas_client::pseudonym_service::PseudonymService;
use paas_client::sessions::EncryptionContexts;

pub fn command() -> Command {
    Command::new("pseudonymize")
        .about("Pseudonymize an encrypted pseudonym from one domain to another")
        .arg(
            Arg::new("encrypted_pseudonym")
                .help("The encrypted pseudonym to pseudonymize")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("sessions")
                .help("The sessions in which the pseudonym was encrypted")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("domain_from")
                .help("The source domain of the pseudonym")
                .required(true)
                .index(3),
        )
        .arg(
            Arg::new("domain_to")
                .help("The target domain of the pseudonym")
                .required(true)
                .index(4),
        )
        .arg(
            Arg::new("no_decrypt")
                .help("Only show the transcrypted result without decrypting")
                .long("no-decrypt")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("state_path")
                .help("Path to restore state from and dump state to")
                .long("state")
                .short('s')
                .value_parser(clap::value_parser!(String)),
        )
}

pub async fn execute<'a>(matches: &clap::ArgMatches, service: &mut PseudonymService<'a>) {
    let encrypted_pseudonym_str = matches
        .get_one::<String>("encrypted_pseudonym")
        .expect("encrypted_pseudonym is required");

    let encrypted_pseudonym = EncryptedPseudonym::from_base64(encrypted_pseudonym_str)
        .expect("Failed to deserialize encrypted_pseudonym");

    let sessions_str = matches
        .get_one::<String>("sessions")
        .expect("sessions is required");

    let sessions =
        EncryptionContexts::decode(sessions_str).expect("Failed to deserialize sessions");

    let domain_from_str = matches
        .get_one::<String>("domain_from")
        .expect("domain_from is required");

    let domain_from = PseudonymizationDomain::from(domain_from_str);

    let domain_to_str = matches
        .get_one::<String>("domain_to")
        .expect("domain_to is required");

    let domain_to = PseudonymizationDomain::from(domain_to_str);

    let result = service
        .pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to)
        .await;

    if matches.get_flag("no_decrypt") {
        eprint!("Transcryption returned: ");
        println!("{}", &result.as_base64());
    } else {
        let pseudonym = service.decrypt(&result).await;
        eprint!("Decrypted pseudonym: ");
        println!("{}", &pseudonym.encode_as_hex());
    }
}
