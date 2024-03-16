use core::fmt::{Display, Formatter};
use sha2::{Sha256, Sha512, Digest};
use base64::{engine::general_purpose, Engine};
use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum HashingError {
    #[error("custom alphabet too short")]
    CustomAlphabetTooShort,
    #[error("deserialization error")]
    Deserialization(serde_json::Error),
}

pub type Result<T> = core::result::Result<T, HashingError>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashingAlgorithm {
    Sha256,
    Sha512
}

impl Default for HashingAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Hex,
    Base64,
    Base64Url,
    CustomAlphabet(String),
}

impl Default for DigestAlgorithm {
    fn default() -> Self {
        Self::Base64
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub enum SaltingAlgorithm {
    Prepend,
    Append,
    Zip(usize),
}

impl Default for SaltingAlgorithm {
    fn default() -> Self {
        Self::Prepend
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlgorithmSettings {
    pub hashing: HashingAlgorithm,
    pub max_length: Option<usize>,
    pub digest: DigestAlgorithm,
    pub salting: SaltingAlgorithm,
    pub hashing_iterations: usize,
    pub salting_iterations: usize,
}

impl Display for AlgorithmSettings {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let res = serde_json::to_string(self).unwrap();
        f.write_str(&res)
    }
}

impl Default for AlgorithmSettings {
    fn default() -> Self {
        Self {
            hashing: Default::default(),
            max_length: None,
            digest: Default::default(),
            salting: Default::default(),
            hashing_iterations: 1,
            salting_iterations: 1,
        }
    }
}

impl AlgorithmSettings {
    pub fn from_string(str: &str) -> Result<Self> {
        let res = serde_json::from_str(str);
        match res {
            Ok(r) => Ok(r),
            Err(e) => Err(HashingError::Deserialization(e)),
        }
    }
}

pub fn digest(digest_algorithm: &DigestAlgorithm, data: &[u8]) -> Result<String> {
    match digest_algorithm {
        DigestAlgorithm::Base64 => Ok(general_purpose::STANDARD.encode(data)),
        DigestAlgorithm::Base64Url => Ok(base64_url::encode(data)),
        DigestAlgorithm::Hex => Ok(hex::encode(data)),
        DigestAlgorithm::CustomAlphabet(alphabet) => {
            if alphabet.len() < 16 {
                Err(HashingError::CustomAlphabetTooShort)
            } else {
                let mut alphabet = alphabet.chars().collect::<Vec<char>>();
                alphabet.sort_unstable();

                let alphabet_length: BigUint = alphabet.len().into();

                let mut bigint = BigUint::from_bytes_le(data);

                let mut result = String::with_capacity(data.len());

                while bigint > Zero::zero() {
                    let digit_idx = (&bigint % &alphabet_length)
                        .to_u64_digits().first()
                        .copied()
                        .unwrap_or(0);

                    let ch = alphabet.get(digit_idx as usize)
                        .copied()
                        .unwrap();
                    result.push(ch);

                    bigint /= &alphabet_length;
                }

                Ok(result)
            }
        },
    }
}

pub fn hash(hashing_algorithm: &HashingAlgorithm, data: &[u8]) -> Vec<u8> {
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

pub fn salt(salting_algorithm: &SaltingAlgorithm, data: &[u8], salt: &[u8]) -> Vec<u8> {
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
        SaltingAlgorithm::Zip(n) => {
            salt.chunks(*n)
                .zip(data.chunks(*n))
                .flat_map(|n| {
                    let mut vec = Vec::with_capacity(n.0.len() + n.1.len());
                    vec.extend_from_slice(n.0);
                    vec.extend_from_slice(n.1);
                    vec
                })
                .collect()
        },
    }
}

pub fn encode(passphrase: &[u8], code: &[u8], settings: &AlgorithmSettings) -> Result<String> {
    let mut salted = salt(&settings.salting, code, passphrase);

    for _ in 1..settings.salting_iterations {
        salted = salt(&settings.salting, &salted, passphrase);
    }

    let mut hashed = hash(&settings.hashing, &salted);

    for _ in 1..settings.hashing_iterations {
        hashed = hash(&settings.hashing, &hashed);
    }

    let digested = digest(&settings.digest, &hashed)?;

    if let Some(n) = settings.max_length {
        if digested.len() > n {
            Ok(digested[0..n].to_owned())
        } else {
            Ok(digested)
        }
    } else {
        Ok(digested)
    }
}
