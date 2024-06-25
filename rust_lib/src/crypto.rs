use crate::errors::{AppError, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::UnparsedPublicKey;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{KeyPair, RsaKeyPair};
use ring::{rand, signature};

pub struct Crypto;

impl Crypto {
    pub fn generate_keys() -> Result<(signature::Ed25519KeyPair, Vec<u8>, Vec<u8>)> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| ring::error::Unspecified)?;

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| AppError::CryptoError)?;

        let public_key = key_pair.public_key().as_ref().to_vec();
        let private_key = pkcs8_bytes.as_ref().to_vec();

        Ok((key_pair, private_key, public_key))
    }

    pub fn generate_symmetric_key() -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 32]; // AES-256 key size
        rng.fill(&mut key).map_err(|_| ring::error::Unspecified)?;
        Ok(key)
    }

        pub fn encrypt_message(message: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce).map_err(|_| ring::error::Unspecified)?;

        // create a copy of nonce for later use to prevent moving the original
        let nonce_copy = nonce;
        let nonce = Nonce::assume_unique_for_key(nonce);

        let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| ring::error::Unspecified)?;
        let key = LessSafeKey::new(key);

        let mut in_out = message.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| ring::error::Unspecified)?;

        let mut result = nonce_copy.to_vec();
        result.extend_from_slice(&in_out);

        Ok((result, nonce_copy.to_vec()))
    }

    pub fn decrypt_message(
        encrypted_message: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>> {
        let (nonce_bytes, ciphertext) = encrypted_message.split_at(12);
        let nonce =
            Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| ring::error::Unspecified)?;

        let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| ring::error::Unspecified)?;
        let key = LessSafeKey::new(key);

        let mut in_out = ciphertext.to_vec();
        key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| ring::error::Unspecified)?;
        let len = in_out.len() - AES_256_GCM.tag_len();
        in_out.truncate(len);
        Ok(in_out)
    }

    pub fn encrypt_symmetric_key(symmetric_key: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>> {
    // Create an UnparsedPublicKey object with the recipient's public key.
    let recipient_public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, recipient_public_key);

    // Encrypt the symmetric key using the recipient's public key.
    let encrypted_key = recipient_public_key.encrypt(&symmetric_key)?;

    // Return the encrypted symmetric key as a vector of bytes.
    Ok(encrypted_key.to_vec())
}

    pub fn decrypt_symmetric_key(encrypted_symmetric_key: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Load the private key from DER-encoded bytes.
    let private_key = RsaKeyPair::from_der(private_key).map_err(|_| AppError::CryptoError)?;

    // Create a buffer to hold the decrypted key.
    let mut decrypted_key = vec![0; private_key.public_modulus_len()];

    // Decrypt the symmetric key using the private key.
    private_key
        .decrypt(&ring::signature::RSA_PKCS1_OAEP_SHA256, &encrypted_symmetric_key, &mut decrypted_key)
        .map_err(|_| AppError::CryptoError)?;

    // Return the decrypted symmetric key.
    Ok(decrypted_key)
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
            Err(e) => panic!("Key pair generation failed: {:?}", e),
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
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);

        // Verifies the signature of the message using the public key
        // and the original message. If the signature is invalid, an error is returned.
        assert!(peer_public_key.verify(MESSAGE, sig.as_ref()).is_ok());
    }
}
