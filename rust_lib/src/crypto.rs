use ring::signature::KeyPair;
use ring::{rand, signature};
use crate::errors::Result;

pub struct Crypto;

impl Crypto {
    pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>)> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| ring::error::Unspecified)?;

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| ring::error::Unspecified)?;

        Ok((pkcs8_bytes.as_ref().to_vec(), key_pair.public_key().as_ref().to_vec()))
    }
}
