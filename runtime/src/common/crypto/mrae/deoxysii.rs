//! Deoxys-II-256-128 MRAE primitives implementation.
use anyhow::Result;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha512_256;
use x25519_dalek::{PublicKey, StaticSecret};

pub use deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE};

type Kdf = Hmac<Sha512_256>;

/// An abstract Deoxys-II-256-128 box opener.
pub trait Opener: Send + Sync {
    /// Unboxes ("opens") the provided additional data and ciphertext.
    fn box_open(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        peers_public_key: &PublicKey,
    ) -> Result<Vec<u8>>;
}

/// Derives a MRAE AEAD symmetric key suitable for use with the asymmetric
/// box primitives from the provided X25519 public and private keys.
fn derive_symmetric_key(public: &PublicKey, private: &StaticSecret) -> [u8; KEY_SIZE] {
    let pmk = private.diffie_hellman(public);

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
pub fn generate_key_pair() -> (PublicKey, StaticSecret) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);

    (pk, sk)
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
    peers_public_key: &PublicKey,
    private_key: &StaticSecret,
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
    peers_public_key: &PublicKey,
    private_key: &StaticSecret,
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
        assert_ne!(a_pub.to_bytes(), b_pub.to_bytes());
        assert_ne!(a_priv.to_bytes(), b_priv.to_bytes());
        assert_ne!(a_pub.to_bytes(), a_priv.to_bytes());
        assert_ne!(b_pub.to_bytes(), b_priv.to_bytes());

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
