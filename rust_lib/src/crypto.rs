use ring::signature::KeyPair;
use ring::{rand, signature};
use crate::errors::Result;

pub struct Crypto;

impl Crypto {
    pub fn generate_keys() -> Result<(signature::Ed25519KeyPair, Vec<u8>, Vec<u8>)> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| ring::error::Unspecified)?;

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| ring::error::Unspecified)?;

        let public_key =  key_pair.public_key().as_ref().to_vec();
        let private_key = pkcs8_bytes.as_ref().to_vec();

        Ok((key_pair, private_key, public_key))
    }
}

#[cfg(test)]

mod tests {

    use super::*;

    #[test]
    fn test_key_generation() {
        match Crypto::generate_keys() {
            Ok((_, private_key, public_key)) => {
                // Ensure keys are not empty
                assert!(!private_key.is_empty(), "Private key should not be empty");
                assert!(!public_key.is_empty(), "Public key should not be empty");

                // Ensure the keys have the right length for Ed25519
                assert_eq!(private_key.len(), 83, "Private key length should be 83 bytes");
                assert_eq!(public_key.len(), 32, "Public key length should be 32 bytes");

            },
            Err(e) => panic!("Key pair generation failed: {:?}", e)
        }
    }

    #[test]
    fn test_signature() {
        const MESSAGE: &[u8] = b"Hello SPEEM";
        let keys = Crypto::generate_keys().unwrap();
        let sig = keys.0.sign(MESSAGE);

        // Typically, a peer would extract the public_key from the key_pair
        // and uses it to verify the signature of the received message
        // Our 'generate_keys()' function already extracts the keys for us
        // but for our test we'll use the key_pair to mimic the right behaviour
        let peer_public_key_bytes = keys.0.public_key().as_ref();

        // Creates an UnparsedPublicKey object using the extracted public key bytes and the Ed25519 algorithm
        let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);

        // Verifies the signature of the message using the public key
        // and the original message. If the signature is invalid, an error is returned.
        assert!(peer_public_key.verify(MESSAGE, sig.as_ref()).is_ok());
    }
}
