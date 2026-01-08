use clap::{Arg, Command};
use libpep::core::data::{Encryptable, Pseudonym};
use paas_client::pseudonym_service::PseudonymService;
use rand::rng;

pub fn command() -> Command {
    Command::new("encrypt").about("Encrypt a pseudonym").arg(
        Arg::new("pseudonym")
            .help("The pseudonym value to encrypt")
            .required(true)
            .index(1),
    )
}

pub async fn execute(matches: &clap::ArgMatches, service: &mut PseudonymService) {
    let pseudonym_string = matches
        .get_one::<String>("pseudonym")
        .expect("pseudonym is required");
    let pseudonym = Pseudonym::from_hex(pseudonym_string).expect("Failed to decode pseudonym");

    let mut rng = rng();

    let (encrypted, sessions) = service
        .encrypt(&pseudonym, &mut rng)
        .expect("Failed to encrypt");

    println!("Encrypted pseudonym: {}", encrypted.to_base64());
    println!("Sessions: {}", sessions.encode());
}
