//! Deoxys-II-256-128 MRAE primitives implementation.

pub use super::deoxysii_rust::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE};

use super::{
    hmac::{Hmac, Mac, NewMac},
    sha2::Sha512Trunc256,
    x25519_dalek,
};

use anyhow::Result;
use rand::rngs::OsRng;

type Kdf = Hmac<Sha512Trunc256>;

/// Derives a MRAE AEAD symmetric key suitable for use with the asymmetric
/// box primitives from the provided X25519 public and private keys.
fn derive_symmetric_key(public: &[u8; 32], private: &[u8; 32]) -> [u8; KEY_SIZE] {
    let public = x25519_dalek::PublicKey::from(*public);
    let private = x25519_dalek::StaticSecret::from(*private);

    let pmk = private.diffie_hellman(&public);

    let mut kdf = Kdf::new_from_slice(b"MRAE_Box_Deoxys-II-256-128").expect("Hmac::new_from_slice");
    kdf.update(pmk.as_bytes());
    drop(pmk);

    let mut derived_key = [0u8; KEY_SIZE];
    let digest = kdf.finalize();
    derived_key.copy_from_slice(&digest.into_bytes()[..KEY_SIZE]);

    derived_key
}

/// Generates a public/private key pair suitable for use with
/// `derive_symmetric_key`, `box_seal`, and `box_open`.
pub fn generate_key_pair() -> ([u8; 32], [u8; 32]) {
    let mut rng = OsRng {};

    let sk = x25519_dalek::StaticSecret::new(&mut rng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    (*pk.as_bytes(), sk.to_bytes())
}

/// Boxes ("seals") the provided additional data and plaintext via
/// Deoxys-II-256-128 using a symmetric key derived from the provided
/// X25519 public and private keys.
/// The nonce should be `NONCE_SIZE` bytes long and unique for all time
/// for a given public and private key tuple.
pub fn box_seal(
    nonce: &[u8; NONCE_SIZE],
    plaintext: Vec<u8>,
    additional_data: Vec<u8>,
    peers_public_key: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let key = derive_symmetric_key(peers_public_key, private_key);

    let d2 = DeoxysII::new(&key);

    Ok(d2.seal(nonce, plaintext, additional_data))
}

/// Unboxes ("opens") the provided additional data and ciphertext via
/// Deoxys-II-256-128 using a symmetric key derived from the provided
/// X25519 public and private keys.
/// The nonce should be `NONCE_SIZE` bytes long and both it and the additional
/// data must match the value passed to `box_seal`.
pub fn box_open(
    nonce: &[u8; NONCE_SIZE],
    ciphertext: Vec<u8>,
    additional_data: Vec<u8>,
    peers_public_key: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let key = derive_symmetric_key(peers_public_key, private_key);

    let d2 = DeoxysII::new(&key);

    d2.open(nonce, ciphertext, additional_data)
        .map_err(|err| err.into())
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::{black_box, Bencher};
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_mrae_asymmetric() {
        let (a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, b_priv) = generate_key_pair(); // Bob

        // None of the generated keys should be the same.
        assert_ne!(a_pub, b_pub);
        assert_ne!(a_priv, b_priv);
        assert_ne!(a_pub, a_priv);
        assert_ne!(b_pub, b_priv);

        // Should successfully seal the text in a box.
        let nonce = [1u8; NONCE_SIZE];
        let text = String::from("This is a test!").as_bytes().to_vec();
        let aad = vec![42u8; 10];

        let sealed = box_seal(&nonce, text.clone(), aad.clone(), &b_pub, &a_priv);
        assert!(sealed.is_ok());

        // Should successfully open the sealed box.
        let opened = box_open(&nonce, sealed.unwrap(), aad, &a_pub, &b_priv);
        assert!(opened.is_ok());

        // The deciphered text should match the original.
        let deciphered = opened.unwrap();
        assert_eq!(deciphered, text);
    }

    #[bench]
    fn bench_mrae_box_seal_4096(b: &mut Bencher) {
        let mut rng = OsRng {};

        // Set up the keys.
        let (_a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, _b_priv) = generate_key_pair(); // Bob

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill_bytes(&mut text);
        let mut aad = [0u8; 64];
        rng.fill_bytes(&mut aad);

        // Benchmark box sealing.
        b.iter(|| {
            let _sealed = black_box(box_seal(
                &nonce,
                text.to_vec(),
                aad.to_vec(),
                &b_pub,
                &a_priv,
            ));
        });
    }

    #[bench]
    fn bench_mrae_box_open_4096(b: &mut Bencher) {
        let mut rng = OsRng {};

        // Set up the keys.
        let (a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, b_priv) = generate_key_pair(); // Bob

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill_bytes(&mut text);
        let mut aad = [0u8; 64];
        rng.fill_bytes(&mut aad);

        // Seal the payload.
        let sealed = box_seal(&nonce, text.to_vec(), aad.to_vec(), &b_pub, &a_priv);
        let ciphertext = sealed.unwrap();

        // Benchmark box opening.
        b.iter(|| {
            let _opened = black_box(box_open(
                &nonce,
                ciphertext.clone(),
                aad.to_vec(),
                &a_pub,
                &b_priv,
            ));
        });
    }
}
