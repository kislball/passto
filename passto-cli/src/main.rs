use clap::Parser;
use passto::{AlgorithmSettings, DigestAlgorithm, encode, HashingAlgorithm, SaltingAlgorithm};
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Digest algorithm
    #[arg(long)]
    digest: Option<DigestAlgorithm>,
    /// Hashing algorithm
    #[arg(long)]
    hashing: Option<HashingAlgorithm>,
    /// Salting algorithm
    #[arg(long)]
    salting: Option<SaltingAlgorithm>,
    /// Max length for your password
    #[arg(long)]
    max_length: Option<usize>,
    /// Salt used for your password. Random by default
    #[arg(long)]
    salt: Option<String>,
    /// Code name for your password
    service: String,
}

fn main() {
    let args = Args::parse();
    let settings = AlgorithmSettings {
        hashing: args.hashing.unwrap_or_default(),
        max_length: args.max_length,
        digest: args.digest.unwrap_or_default(),
        salting: args.salting.unwrap_or_default(),
    };
    
    let salt = if let Some(str) = args.salt {
        str.as_bytes().to_vec()
    } else {
        let mut buf = Vec::with_capacity(32);
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut buf);
        buf
    };
    
    let service = args.service.as_bytes();
    
    let res = encode(&salt, service, &settings);
    println!("{res}");
}
