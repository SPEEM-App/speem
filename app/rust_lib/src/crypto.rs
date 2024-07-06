use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePrivateKey, RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use crate::errors::{AppError, Result};

pub struct Crypto;

impl Crypto {
	pub fn generate_keys() -> Result<(Ed25519KeyPair, Vec<u8>, Vec<u8>)> {
		let rng = SystemRandom::new();
		let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
			.map_err(|_| ring::error::Unspecified)?;

		let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
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

	pub fn decrypt_message(encrypted_message: &[u8], key: &[u8]) -> Result<Vec<u8>> {
		let (nonce_bytes, ciphertext) = encrypted_message.split_at(12);
		let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
			.map_err(|_| ring::error::Unspecified)?;

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
		// Decode the recipient's public key from its DER-encoded form
		let public_key = RsaPublicKey::from_pkcs1_der(recipient_public_key)
			.map_err(|_| AppError::CryptoError)?;

		// Encrypt the symmetric key using the recipient's public key
		let mut rng = rand::thread_rng();
		let encrypted_key = public_key
			.encrypt(&mut rng, Pkcs1v15Encrypt, symmetric_key)
			.map_err(|_| AppError::CryptoError)?;

		// Return the encrypted symmetric key
		Ok(encrypted_key)
	}

	pub fn decrypt_symmetric_key(encrypted_symmetric_key: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
		// Decode the private key from its DER-encoded form
		let private_key = RsaPrivateKey::from_pkcs8_der(private_key)
			.map_err(|_| AppError::CryptoError)?;

		// Decrypt the symmetric key using the private key
		let decrypted_key = private_key
			.decrypt(Pkcs1v15Encrypt, encrypted_symmetric_key)
			.map_err(|_| AppError::CryptoError)?;

		// Return the decrypted symmetric key
		Ok(decrypted_key)
	}

	pub fn generate_mnemonic() -> Result<(String, String)> {
		let rng = SystemRandom::new();
		let mut entropy = vec![0u8; 4];
		rng.fill(&mut entropy).map_err(|_| ring::error::Unspecified).map_err(|_| AppError::CryptoError)?;
		let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|_| AppError::CryptoError)?;
		let mut mnemonic_phrase = String::from("");
		let _ = mnemonic.word_iter().map(|word| mnemonic_phrase.push_str(format!("{word} ").as_str()));
		let seed = mnemonic.to_seed("");
		let encryption_key = hex::encode(&seed[0..32]);
		Ok((mnemonic_phrase.trim_end().to_owned(), encryption_key))
	}

	pub fn mnemonic_to_key(mnemonic_phrase: &str) -> Result<String> {
		let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English)
			.map_err(|_| AppError::CryptoError)?;
		let seed = mnemonic.to_seed("");
		let encryption_key = hex::encode(&seed[0..32]);
		Ok(encryption_key)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ring::signature;
	use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey, pkcs8::EncodePrivateKey};

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

	#[test]
	fn test_generate_symmetric_key() {
		let symmetric_key = Crypto::generate_symmetric_key().unwrap();
		assert_eq!(symmetric_key.len(), 32);
	}

	#[test]
	fn test_encrypt_decrypt_message() {
		let message = b"Test message";
		let symmetric_key = Crypto::generate_symmetric_key().unwrap();

		let (encrypted_message, _nonce) = Crypto::encrypt_message(message, &symmetric_key).unwrap();
		let decrypted_message = Crypto::decrypt_message(&encrypted_message, &symmetric_key).unwrap();

		assert_eq!(message.to_vec(), decrypted_message);
	}

	#[test]
	fn test_encrypt_decrypt_symmetric_key() {
		let symmetric_key = Crypto::generate_symmetric_key().unwrap();

		let mut rng = rand::thread_rng();
		let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate private key");
		let public_key = RsaPublicKey::from(&private_key);

		let private_key_der = private_key.to_pkcs8_der().unwrap();
		let public_key_der = public_key.to_pkcs1_der().unwrap();

		let encrypted_key = Crypto::encrypt_symmetric_key(&symmetric_key, &public_key_der.as_bytes()).unwrap();
		let decrypted_key = Crypto::decrypt_symmetric_key(&encrypted_key, &private_key_der.as_bytes()).unwrap();

		assert_eq!(symmetric_key, decrypted_key);
	}
}