//! SIV_CTR-AES128_HMAC-SHA256-128 MRAE primitives implementation.
use byteorder::{BigEndian, ByteOrder};
use failure::{format_err, Fallible};
use rand::rngs::OsRng;

use super::{
    aes::{block_cipher_trait::generic_array::GenericArray, Aes128},
    block_modes::{block_padding::ZeroPadding, BlockMode, BlockModeIv, Ctr128},
    crypto_ops::{fixed_time_eq, secure_memset},
    ring::{digest, hmac},
    x25519_dalek,
};

/// Size of the expanded SIV_CTR-AES128_HMAC-SHA256-128 key in bytes.
pub const KEY_SIZE: usize = 48;
/// Size of the authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

pub struct SivAesSha2 {
    mac_key: Vec<u8>, // 32 bytes
    ctr_key: Vec<u8>, // 16 bytes
}

impl Drop for SivAesSha2 {
    /// Make sure the keys are erased before the struct is dropped.
    fn drop(&mut self) {
        secure_memset(&mut self.mac_key, 0u8);
        secure_memset(&mut self.ctr_key, 0u8);
    }
}

impl SivAesSha2 {
    /// Creates a new instance using the provided `key`, which must be
    /// `KEY_SIZE` bytes long or an "invalid key size" error will be returned.
    pub fn new(key: Vec<u8>) -> Fallible<Self> {
        if key.len() != KEY_SIZE {
            return Err(format_err!("sivaessha2: invalid key size"));
        }

        // First 32 bytes is the key for HMAC.
        let mut mac_key = Vec::with_capacity(32);
        mac_key.extend_from_slice(&key[0..32]);

        // The remaining 16 bytes is the key for AES-CTR.
        let mut ctr_key = Vec::with_capacity(16);
        ctr_key.extend_from_slice(&key[32..]);

        Ok(Self { mac_key, ctr_key })
    }

    /// Packs the lengths of the additional data and plaintext vectors
    /// into an 8-byte u8 vector as two u32 big-endian values.
    /// Checks for overflow and returns either "invalid AAD size" or
    /// "invalid plaintext size", depending on which value would have
    /// overflowed.
    fn get_len_vec(aad_len: usize, pt_len: usize) -> Fallible<Vec<u8>> {
        // Check for overflows first!
        if aad_len as u64 > <u32>::max_value() as u64 {
            return Err(format_err!("sivaessha2: invalid AAD size"));
        }

        if pt_len as u64 > <u32>::max_value() as u64 {
            return Err(format_err!("sivaessha2: invalid plaintext size"));
        }

        let mut buf = [0; 8];
        BigEndian::write_u32(&mut buf[..4], aad_len as u32);
        BigEndian::write_u32(&mut buf[4..], pt_len as u32);

        Ok(buf.to_vec())
    }

    /// Encrypts and authenticates plaintext, authenticates the additional
    /// data and returns the result.
    /// The nonce should be `NONCE_SIZE` bytes long and unique for all time
    /// for a given key (but arbitrary lengths are accepted).
    pub fn seal(
        &self,
        nonce: Vec<u8>,
        plaintext: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Fallible<Vec<u8>> {
        let pt_len = plaintext.len();
        let aad_len = additional_data.len();

        // First, we do a HMAC on the message using the mac_key.
        let hmac_key = hmac::SigningKey::new(&digest::SHA256, &self.mac_key.as_slice());
        let mut ctx = hmac::SigningContext::with_key(&hmac_key);

        // Message is composed of the following:
        // NONCE | uint32(len(AAD)) | uint32(len(P)) | AAD | P
        ctx.update(&nonce);
        ctx.update(&Self::get_len_vec(aad_len, pt_len)?);
        ctx.update(&additional_data);
        ctx.update(&plaintext);

        let hmac_sig = ctx.sign();

        // Now we have our initialization vector for AES-CTR.
        let siv = &hmac_sig.as_ref()[..TAG_SIZE];

        // Encrypt the plaintext using ctr_key and the siv initialization vector.
        let mut ctr = Ctr128::<Aes128, ZeroPadding>::new_varkey(
            &self.ctr_key.as_slice(),
            GenericArray::from_slice(siv),
        )
        .unwrap();
        let mut c: Vec<u8> = plaintext.clone();

        // The block_modes CTR mode requires things to be aligned to block sizes!
        let offset = c.len() % 16;
        let align = c.len() - offset;

        ctr.encrypt_nopad(&mut c[..align]).unwrap();

        if offset != 0 {
            let mut blk = [0u8; 16];
            ctr.encrypt_nopad(&mut blk).unwrap();

            let a = &mut c[align..];
            let b = &blk[..offset];
            for i in 0..b.len() {
                a[i] ^= b[i];
            }
        }

        // Append siv to the result and return.
        c.extend_from_slice(&siv);

        Ok(c)
    }

    /// Decrypts and authenticates ciphertext, authenticates the additional
    /// data and, if successful, returns the resulting plaintext.
    pub fn open(
        &self,
        nonce: Vec<u8>,
        ciphertext_with_tag: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Fallible<Vec<u8>> {
        if ciphertext_with_tag.len() < TAG_SIZE {
            return Err(format_err!("sivaessha2: ciphertext too short"));
        }

        let pt_len = ciphertext_with_tag.len() - TAG_SIZE;
        let aad_len = additional_data.len();

        // Decrypt the ciphertext first.
        let ciphertext = &ciphertext_with_tag[..pt_len];
        let siv = &ciphertext_with_tag[pt_len..];

        let mut ctr = Ctr128::<Aes128, ZeroPadding>::new_varkey(
            &self.ctr_key.as_slice(),
            GenericArray::from_slice(siv),
        )
        .unwrap();
        let mut p: Vec<u8> = ciphertext.to_vec();

        // The block_modes crate requires things to be aligned to block sizes.
        let offset = p.len() % 16;
        let align = p.len() - offset;

        ctr.decrypt_nopad(&mut p[..align]).unwrap();

        if offset != 0 {
            let mut blk = [0u8; 16];
            ctr.decrypt_nopad(&mut blk).unwrap();

            let a = &mut p[align..];
            let b = &blk[..offset];
            for i in 0..b.len() {
                a[i] ^= b[i];
            }
        }

        // Now we're going to do a HMAC on the message using the mac_key again.
        let hmac_key = hmac::SigningKey::new(&digest::SHA256, &self.mac_key.as_slice());
        let mut ctx = hmac::SigningContext::with_key(&hmac_key);

        // Message is composed of the following:
        // NONCE | uint32(len(AAD)) | uint32(len(P)) | AAD | P
        ctx.update(&nonce);
        ctx.update(&Self::get_len_vec(aad_len, pt_len)?);
        ctx.update(&additional_data);
        ctx.update(&p);

        let hmac_sig = ctx.sign();
        let siv_cmp = &hmac_sig.as_ref()[..TAG_SIZE];

        // Verify if signatures match.
        if !fixed_time_eq(siv, siv_cmp) {
            // Clear memory on failure.
            secure_memset(&mut p, 0u8);
            return Err(format_err!("sivaessha2: message authentication failed"));
        }

        Ok(p)
    }
}

/// Derives a MRAE AEAD symmetric key suitable for use with the asymmetric
/// box primitives from the provided X25519 public and private keys.
fn derive_symmetric_key(public: &[u8; 32], private: &[u8; 32]) -> [u8; KEY_SIZE] {
    let public = x25519_dalek::PublicKey::from(public.clone());
    let private = x25519_dalek::StaticSecret::from(private.clone());

    let pmk = private.diffie_hellman(&public);

    let k = hmac::SigningKey::new(&digest::SHA384, b"MRAE_Box_SIV_CTR-AES128_HMAC-SHA256-128");
    let mut ctx = hmac::SigningContext::with_key(&k);

    ctx.update(pmk.as_bytes());
    drop(pmk);

    let mut derived_key = [0u8; KEY_SIZE];
    derived_key.copy_from_slice(&ctx.sign().as_ref()[..KEY_SIZE]);

    derived_key
}

/// Generates a public/private key pair suitable for use with
/// `derive_symmetric_key`, `box_seal`, and `box_open`.
pub fn generate_key_pair() -> ([u8; 32], [u8; 32]) {
    let mut rng = OsRng::new().unwrap();

    let sk = x25519_dalek::StaticSecret::new(&mut rng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    (pk.as_bytes().clone(), sk.to_bytes())
}

/// Boxes ("seals") the provided additional data and plaintext via
/// SIV_CTR-AES128_HMAC-SHA256-128 using a symmetric key derived from the
/// provided X25519 public and private keys.
/// The nonce should be `NONCE_SIZE` bytes long and unique for all time
/// for a given public and private key tuple.
pub fn box_seal(
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    additional_data: Vec<u8>,
    peers_public_key: [u8; 32],
    private_key: [u8; 32],
) -> Fallible<Vec<u8>> {
    let key = derive_symmetric_key(&peers_public_key, &private_key);

    let siv = SivAesSha2::new(key.to_vec())?;

    siv.seal(nonce, plaintext, additional_data)
}

/// Unboxes ("opens") the provided additional data and ciphertext via
/// SIV_CTR-AES128_HMAC-SHA256-128 using a symmetric key derived from the
/// provided X25519 public and private keys.
/// The nonce should be `NONCE_SIZE` bytes long and both it and the additional
/// data must match the value passed to `box_seal`.
pub fn box_open(
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    additional_data: Vec<u8>,
    peers_public_key: [u8; 32],
    private_key: [u8; 32],
) -> Fallible<Vec<u8>> {
    let key = derive_symmetric_key(&peers_public_key, &private_key);

    let siv = SivAesSha2::new(key.to_vec())?;

    siv.open(nonce, ciphertext, additional_data)
}

#[cfg(test)]
mod tests {
    extern crate base64;
    extern crate serde_json;
    extern crate test;

    use rand::Rng;

    use self::{
        base64::decode,
        serde_json::{Map, Value},
        test::{black_box, Bencher},
    };
    use super::{super::nonce::NONCE_SIZE, *};

    #[test]
    fn test_mrae_basic() {
        // Should fail with "invalid key size".
        let failed_siv = SivAesSha2::new(vec![0; 10]);
        assert!(failed_siv.is_err());

        // Should succeed.
        let siv = SivAesSha2::new(vec![0; KEY_SIZE]);
        assert!(siv.is_ok());
        let siv = siv.unwrap();

        // Should successfully seal the text.
        let nonce = vec![1; NONCE_SIZE];
        let text = String::from("This is a test!").as_bytes().to_vec();
        let aad = vec![42; 10];
        let sealed = siv.seal(nonce.clone(), text.clone(), aad.clone());
        assert!(sealed.is_ok());
        let ciphertext = sealed.unwrap();

        // Should successfully open the text and the text should match.
        let opened = siv.open(nonce.clone(), ciphertext.clone(), aad.clone());
        assert!(opened.is_ok());
        assert!(opened.unwrap() == text);

        // Should fail if the nonce is different.
        let fake_nonce = vec![2; NONCE_SIZE];
        let fail_opened = siv.open(fake_nonce.clone(), ciphertext.clone(), aad.clone());
        assert!(fail_opened.is_err());

        // Should fail if the additional data is different.
        let fake_aad = vec![47; 10];
        let fail_opened = siv.open(nonce.clone(), ciphertext.clone(), fake_aad.clone());
        assert!(fail_opened.is_err());

        // Should fail if the both the nonce and the additional data are different.
        let fake_nonce = vec![3; NONCE_SIZE];
        let fake_aad = vec![4; 5];
        let fail_opened = siv.open(fake_nonce.clone(), ciphertext.clone(), fake_aad.clone());
        assert!(fail_opened.is_err());

        // Should handle too short ciphertext.
        let fail_opened = siv.open(nonce.clone(), vec![1, 2, 3], aad.clone());
        assert!(fail_opened.is_err());

        // Should fail on damaged ciphertext.
        let mut malformed_ciphertext = ciphertext.clone();
        malformed_ciphertext[3] ^= 0xa5;
        let fail_opened = siv.open(nonce.clone(), malformed_ciphertext, aad.clone());
        assert!(fail_opened.is_err());

        // Should fail on truncated ciphertext.
        let mut truncated_ciphertext = ciphertext.clone();
        truncated_ciphertext.truncate(ciphertext.len() - 5);
        let fail_opened = siv.open(nonce.clone(), truncated_ciphertext, aad.clone());
        assert!(fail_opened.is_err());
    }

    #[test]
    fn test_mrae_vectors() {
        let test_vectors = include_str!("../../../../../go/common/crypto/mrae/sivaessha2/testdata/SIV_CTR-AES128_HMAC-SHA256-128.json");
        let test_vectors: Map<String, Value> = serde_json::from_str(test_vectors).unwrap();

        let key = decode(test_vectors["Key"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let msg = decode(test_vectors["MsgData"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let aad = decode(test_vectors["AADData"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let nonce = decode(test_vectors["Nonce"].as_str().unwrap())
            .unwrap()
            .to_vec();

        let siv = SivAesSha2::new(key).unwrap();

        for v in test_vectors["KnownAnswers"].as_array().unwrap().iter() {
            let ciphertext = decode(v["Ciphertext"].as_str().unwrap()).unwrap().to_vec();
            let tag = decode(v["Tag"].as_str().unwrap()).unwrap().to_vec();
            let length: usize = v["Length"].as_u64().unwrap() as usize;

            let ct = siv
                .seal(
                    nonce.clone(),
                    msg[..length].to_vec(),
                    aad[..length].to_vec(),
                )
                .unwrap();

            assert_eq!(ct.len(), length + TAG_SIZE);

            let t = ct[length..].to_vec();
            let ct = ct[..length].to_vec();

            assert_eq!(ciphertext, ct);
            assert_eq!(tag, t);
        }
    }

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
        let nonce = vec![1; NONCE_SIZE];
        let text = String::from("This is a test!").as_bytes().to_vec();
        let aad = vec![42; 10];

        let sealed = box_seal(nonce.clone(), text.clone(), aad.clone(), b_pub, a_priv);
        assert!(sealed.is_ok());

        // Should successfully open the sealed box.
        let opened = box_open(nonce, sealed.unwrap(), aad, a_pub, b_priv);
        assert!(opened.is_ok());

        // The deciphered text should match the original.
        let deciphered = opened.unwrap();
        assert_eq!(deciphered, text);
    }

    #[bench]
    fn bench_mrae_seal_4096(b: &mut Bencher) {
        let mut rng = OsRng::new().unwrap();

        let mut key_nonce = [0u8; KEY_SIZE + NONCE_SIZE];
        rng.fill(&mut key_nonce);
        let key = &key_nonce[..KEY_SIZE];
        let nonce = &key_nonce[KEY_SIZE..];

        // Set up the key.
        let siv = SivAesSha2::new(key.to_vec()).unwrap();

        // Set up the payload.
        let mut text = [0u8; 4096];
        rng.fill(&mut text);
        let mut aad = [0u8; 64];
        rng.fill(&mut aad);

        // Benchmark sealing.
        b.iter(|| {
            let _sealed = black_box(siv.seal(nonce.to_vec(), text.to_vec(), aad.to_vec()));
        });
    }

    #[bench]
    fn bench_mrae_open_4096(b: &mut Bencher) {
        let mut rng = OsRng::new().unwrap();

        let mut key_nonce = [0u8; KEY_SIZE + NONCE_SIZE];
        rng.fill(&mut key_nonce);
        let key = &key_nonce[..KEY_SIZE];
        let nonce = &key_nonce[KEY_SIZE..];

        // Set up the key.
        let siv = SivAesSha2::new(key.to_vec()).unwrap();

        // Set up the payload.
        let mut text = [0u8; 4096];
        rng.fill(&mut text);
        let mut aad = [0u8; 64];
        rng.fill(&mut aad);

        // Seal the payload.
        let sealed = siv.seal(nonce.to_vec(), text.to_vec(), aad.to_vec());
        let ciphertext = sealed.unwrap();

        // Benchmark opening.
        b.iter(|| {
            let _opened = black_box(siv.open(nonce.to_vec(), ciphertext.to_vec(), aad.to_vec()));
        });
    }

    #[bench]
    fn bench_mrae_box_seal_4096(b: &mut Bencher) {
        let mut rng = OsRng::new().unwrap();

        // Set up the keys.
        let (_a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, _b_priv) = generate_key_pair(); // Bob

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill(&mut text);
        let mut aad = [0u8; 64];
        rng.fill(&mut aad);

        // Benchmark box sealing.
        b.iter(|| {
            let _sealed = black_box(box_seal(
                nonce.to_vec(),
                text.to_vec(),
                aad.to_vec(),
                b_pub,
                a_priv,
            ));
        });
    }

    #[bench]
    fn bench_mrae_box_open_4096(b: &mut Bencher) {
        let mut rng = OsRng::new().unwrap();

        // Set up the keys.
        let (a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, b_priv) = generate_key_pair(); // Bob

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill(&mut text);
        let mut aad = [0u8; 64];
        rng.fill(&mut aad);

        // Seal the payload.
        let sealed = box_seal(nonce.to_vec(), text.to_vec(), aad.to_vec(), b_pub, a_priv);
        let ciphertext = sealed.unwrap();

        // Benchmark box opening.
        b.iter(|| {
            let _opened = black_box(box_open(
                nonce.to_vec(),
                ciphertext.clone(),
                aad.to_vec(),
                a_pub,
                b_priv,
            ));
        });
    }
}
