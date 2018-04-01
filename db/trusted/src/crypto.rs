use sodalite;

use ekiden_common::error::{Error, Result};
use ekiden_common::random;

#[cfg(target_env = "sgx")]
use ekiden_key_manager_client::KeyManager;

use super::generated::database::CryptoSecretbox;

const SECRETBOX_ZEROBYTES: usize = 32;

/// Retrieve or generate state secret key.
#[cfg(target_env = "sgx")]
fn get_state_key() -> Result<sodalite::SecretboxKey> {
    let key = KeyManager::get()?.get_or_create_key("state", sodalite::SECRETBOX_KEY_LEN)?;
    let mut state_key = [0; sodalite::SECRETBOX_KEY_LEN];
    state_key.copy_from_slice(key.as_slice());

    Ok(state_key)
}

#[cfg(not(target_env = "sgx"))]
fn get_state_key() -> Result<sodalite::SecretboxKey> {
    // This implementation is used in unit tests (on non-SGX).
    Ok([42; sodalite::SECRETBOX_KEY_LEN])
}

/// Open encrypted state box.
pub fn decrypt_state(encrypted_state: &CryptoSecretbox) -> Result<Vec<u8>> {
    let state_key = get_state_key()?;
    let encrypted_state_ciphertext = encrypted_state.get_ciphertext();

    let mut encrypted_state_nonce: sodalite::SecretboxNonce = [0; sodalite::SECRETBOX_NONCE_LEN];
    encrypted_state_nonce.copy_from_slice(encrypted_state.get_nonce());

    let mut state_raw_padded = vec![0; encrypted_state_ciphertext.len()];

    match sodalite::secretbox_open(
        &mut state_raw_padded,
        encrypted_state_ciphertext,
        &encrypted_state_nonce,
        &state_key,
    ) {
        Ok(_) => {}
        _ => return Err(Error::new("Failed to open state box")),
    }

    Ok(state_raw_padded[SECRETBOX_ZEROBYTES..].to_vec())
}

/// Generate encrypted state box.
pub fn encrypt_state(mut state: Vec<u8>) -> Result<CryptoSecretbox> {
    let state_key = get_state_key()?;

    let mut state_raw_padded = vec![0; SECRETBOX_ZEROBYTES];
    state_raw_padded.append(&mut state);

    let mut encrypted_state_nonce = [0; sodalite::SECRETBOX_NONCE_LEN];
    random::get_random_bytes(&mut encrypted_state_nonce)?;

    let mut encrypted_state_ciphertext = vec![0; state_raw_padded.len()];

    match sodalite::secretbox(
        &mut encrypted_state_ciphertext,
        &state_raw_padded,
        &encrypted_state_nonce,
        &state_key,
    ) {
        Ok(_) => {}
        _ => return Err(Error::new("Failed to create state box")),
    }

    let mut encrypted_state = CryptoSecretbox::new();
    encrypted_state.set_ciphertext(encrypted_state_ciphertext);
    encrypted_state.set_nonce(encrypted_state_nonce.to_vec());

    Ok(encrypted_state)
}
