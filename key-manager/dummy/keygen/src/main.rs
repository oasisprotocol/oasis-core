extern crate ring;
use ring::{rand::SecureRandom, signature::KeyPair};
extern crate serde_cbor;
extern crate untrusted;

extern crate ekiden_keymanager_common;

fn main() {
    let rng = ring::rand::SystemRandom::new();

    // Generate keystore encryption key.
    let mut keystore_encryption_sym: ekiden_keymanager_common::StateKeyType = [0; 64];
    rng.fill(&mut keystore_encryption_sym).unwrap();
    println!("keystore encryption {:?}", &keystore_encryption_sym[..]);

    // Generate signing key.
    let signing_pkcs8_doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    println!("signing pkcs8 {:?}", signing_pkcs8_doc.as_ref());
    let signing_pair = ring::signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(
        signing_pkcs8_doc.as_ref(),
    ))
    .unwrap();
    let signing_public = signing_pair.public_key();
    println!("signing public {:?}", signing_public.as_ref());

    let keys = ekiden_keymanager_common::DummyInternalKeys {
        keystore_encryption_key: keystore_encryption_sym,
        signing_key: signing_pkcs8_doc.as_ref().to_owned(),
    };
    println!(
        "serialized InternalKeys {:?}",
        serde_cbor::to_vec(&keys).unwrap().as_slice()
    );
}
