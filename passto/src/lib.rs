use sha2::{Sha256, Sha512, Digest};
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use clap::ValueEnum;

#[derive(ValueEnum, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab_case")]
pub enum HashingAlgorithm {
    Sha256,
    Sha512
}

impl Default for HashingAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

#[derive(ValueEnum, Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[clap(rename_all = "kebab_case")]
pub enum DigestAlgorithm {
    Hex,
    Base64,
    Base64Url,
}

impl Default for DigestAlgorithm {
    fn default() -> Self {
        Self::Base64
    }
}

#[derive(ValueEnum, Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[clap(rename_all = "kebab_case")]
pub enum SaltingAlgorithm {
    Prepend,
    Append,
    Zip,
}

impl Default for SaltingAlgorithm {
    fn default() -> Self {
        Self::Prepend
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy)]
pub struct AlgorithmSettings {
    pub hashing: HashingAlgorithm,
    pub max_length: Option<usize>,
    pub digest: DigestAlgorithm,
    pub salting: SaltingAlgorithm,
}

impl AlgorithmSettings {
    pub fn to_string(&self) -> String {
        return serde_json::to_string(self).unwrap();
    }
    
    pub fn from_string(str: &str) -> Result<Self, ()> {
        return serde_json::from_str(str).map_err(|_| ())
    }
}

pub fn digest(digest_algorithm: DigestAlgorithm, data: &[u8]) -> String {
    match digest_algorithm {
        DigestAlgorithm::Base64 => general_purpose::STANDARD.encode(data),
        DigestAlgorithm::Base64Url => base64_url::encode(data),
        DigestAlgorithm::Hex => hex::encode(data),
    }
}

pub fn hash(hashing_algorithm: HashingAlgorithm, data: &[u8]) -> Vec<u8> {
    match hashing_algorithm {
        HashingAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        },
        HashingAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
    }
}

pub fn salt(salting_algorithm: SaltingAlgorithm, data: &[u8], salt: &[u8]) -> Vec<u8> {
    match salting_algorithm { 
        SaltingAlgorithm::Append => {
            let mut res = Vec::with_capacity(data.len() + salt.len());
            
            res.extend_from_slice(data);
            res.extend_from_slice(salt);
            
            res
        },
        SaltingAlgorithm::Prepend => {
            let mut res = Vec::with_capacity(data.len() + salt.len());
            
            res.extend_from_slice(salt);
            res.extend_from_slice(data);

            res
        },
        SaltingAlgorithm::Zip => {
            salt.iter().zip(data)
                .flat_map(|n| {
                    vec![*n.0, *n.1]
                })
                .collect()
        },
    }
}

pub fn encode(passphrase: &[u8], code: &[u8], settings: &AlgorithmSettings) -> String {
    let salted = salt(settings.salting, code, passphrase);
    let hashed = hash(settings.hashing, &salted);
    let digested = digest(settings.digest, &hashed);
    
    if let Some(n) = settings.max_length {
        if digested.len() > n {
            (&digested[0..n]).to_owned()
        } else {
            digested
        }
    } else {
        digested
    }
}
