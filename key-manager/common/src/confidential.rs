//! Encryption utilties for web3(c) V0.5 key management.

use ekiden_core::error::{Error, Result};
use ekiden_core::mrae::sivaessha2;

use super::{PrivateKeyType, PublicKeyType, EMPTY_PRIVATE_KEY, EMPTY_PUBLIC_KEY};
use sodalite;

pub fn encrypt(
    plaintext: Vec<u8>,
    nonce: Vec<u8>,
    peer_public_key: PublicKeyType,
    public_key: &PublicKeyType,
    secret_key: &PrivateKeyType,
) -> Result<Vec<u8>> {
    let ciphertext = sivaessha2::box_seal(
        nonce.clone(),
        plaintext.clone(),
        vec![],
        peer_public_key.into(),
        *secret_key,
    )?;
    Ok(encode_encryption(ciphertext, nonce, *public_key))
}

pub fn decrypt(data: Option<Vec<u8>>, secret_key: &PrivateKeyType) -> Result<Decryption> {
    if data.is_none() {
        return Ok(Decryption {
            plaintext: Default::default(),
            peer_public_key: Default::default(),
            nonce: Default::default(),
        });
    }
    let (nonce, peer_public_key, cipher) = split_encrypted_payload(data.unwrap())?;
    let plaintext = sivaessha2::box_open(
        nonce.clone(),
        cipher,
        vec![],
        peer_public_key.into(),
        *secret_key,
    )?;
    Ok(Decryption {
        plaintext,
        peer_public_key,
        nonce: nonce,
    })
}

/// The returned result of decrypting an encrypted payload, where
/// nonce and peer_public_key were used to encrypt the plaintext.
#[derive(Debug, Clone)]
pub struct Decryption {
    pub plaintext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub peer_public_key: PublicKeyType,
}

fn encode_encryption(
    mut ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    public_key: PublicKeyType,
) -> Vec<u8> {
    let mut encryption = nonce;
    encryption.append(&mut public_key.to_vec());
    encryption.append(&mut ciphertext);
    encryption
}

/// Assumes data is of the form  IV || PK || CIPHER.
/// Returns a tuple of each component.
fn split_encrypted_payload(data: Vec<u8>) -> Result<(Vec<u8>, PublicKeyType, Vec<u8>)> {
    let nonce_size = sivaessha2::NONCE_SIZE;
    if data.len() < nonce_size + 32 {
        return Err(Error::new("Invalid nonce or public key"));
    }
    let nonce = data[..nonce_size].to_vec();
    let mut peer_public_key = EMPTY_PUBLIC_KEY;
    peer_public_key.copy_from_slice(&data[nonce_size..nonce_size + 32]);
    let cipher = data[nonce_size + 32..].to_vec();
    Ok((nonce, peer_public_key, cipher))
}
