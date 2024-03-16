use core::fmt::Display;
use core::iter::repeat;
use std::process;
use clap::Parser;
use log::error;
use passto::{AlgorithmSettings, DigestAlgorithm, encode, HashingAlgorithm, SaltingAlgorithm};
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Use sha256 for hashing
    #[arg(long, default_value_t = true)]
    sha256: bool,
    /// Use sha512 for hashing
    #[arg(long, default_value_t = false)]
    sha512: bool,
    /// Use ZIP salting
    #[arg(long)]
    zip: Option<usize>,
    /// Use append salting
    #[arg(long, default_value_t = false)]
    append: bool,
    /// Use prepend salting
    #[arg(long, default_value_t = false)]
    prepend: bool,
    /// Use HEX digest
    #[arg(long, default_value_t = false)]
    hex: bool,
    /// Use Base64 digest
    #[arg(long, default_value_t = true)]
    base64: bool,
    /// Use Base64URL digest
    #[arg(long, default_value_t = false)]
    base64url: bool,
    /// Hashing iterations
    #[arg(long, default_value_t = 1)]
    hashing_iterations: usize,
    /// Salting iterations
    #[arg(long, default_value_t = 1)]
    salting_iterations: usize,
    /// Use custom alphabet
    #[arg(long)]
    alphabet: Option<String>,
    /// Max length for your password
    #[arg(long)]
    max_length: Option<usize>,
    /// Salt used for your password. Random by default
    #[arg(long)]
    salt: Option<String>,
    /// Code name for your password
    service: String,
}

fn build_settings(args: &Args) -> AlgorithmSettings {
    let mut settings = AlgorithmSettings {
        salting_iterations: args.salting_iterations,
        hashing_iterations: args.hashing_iterations,
        max_length: args.max_length,
        ..Default::default()
    };

    if args.append {
        settings.salting = SaltingAlgorithm::Append;
    } else if let Some(n) = args.zip {
        settings.salting = SaltingAlgorithm::Zip(n);
    } else if args.prepend {
        settings.salting = SaltingAlgorithm::Prepend;
    }

    if args.sha512 {
        settings.hashing = HashingAlgorithm::Sha512;
    } else {
        settings.hashing = HashingAlgorithm::Sha256;
    }

    if args.hex {
        settings.digest = DigestAlgorithm::Hex;
    } else if args.base64url {
        settings.digest = DigestAlgorithm::Base64Url;
    } else if let Some(alphabet) = &args.alphabet {
        settings.digest = DigestAlgorithm::CustomAlphabet(alphabet.clone());
    } else if args.base64 {
        settings.digest = DigestAlgorithm::Base64;
    }

    settings
}

fn get_salt(args: &Args) -> Vec<u8> {
    if let Some(str) = &args.salt {
        return str.as_bytes().to_vec()
    } else {
        let mut buf = repeat(0u8).take(32).collect::<Vec<u8>>();
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut buf);
        buf
    }
}

fn handle_res<T: Display>(r: passto::Result<T>) {
    if let Ok(res) = r {
        println!("{res}");
    } else {
        let err = r.err().unwrap();
        error!("{err}");
        process::exit(1);
    }
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();
    
    let args = Args::parse();

    let settings = build_settings(&args);
    let salt = get_salt(&args);

    let service = args.service.as_bytes();

    handle_res(encode(&salt, service, &settings));
}
