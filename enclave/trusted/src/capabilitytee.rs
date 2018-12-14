//! Functionality for implementing RFC 0009 CapabilityTEE.

#[cfg(target_env = "sgx")]
use sgx_tse;
#[cfg(target_env = "sgx")]
use sgx_types;

#[cfg(not(target_env = "sgx"))]
use std::sync::RwLock as SgxRwLock;
#[cfg(target_env = "sgx")]
use std::sync::SgxRwLock;

use ekiden_common::ring::signature::Ed25519KeyPair;

const HASH_CONTEXT: [u8; 8] = *b"EkNodReg";

lazy_static! {
    // Global runtime attestation key.
    static ref RAK: SgxRwLock<Option<Ed25519KeyPair>> = SgxRwLock::new(None);
}

/// Uses ekiden-common's get_random_bytes for Ring's SecureRandom.
struct CommonRng;
impl ekiden_common::ring::rand::SecureRandom for CommonRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), ekiden_common::ring::error::Unspecified> {
        ekiden_common::random::get_random_bytes(dest)
            .map_err(|_| ekiden_common::ring::error::Unspecified)
    }
}

#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn capabilitytee_init(
    rak_pub: &mut [u8; 32],
    target_info: &sgx_types::sgx_target_info_t,
    report: &mut sgx_types::sgx_report_t,
) {
    // Generate new runtime attestation private key.
    let rak_pkcs8 = Ed25519KeyPair::generate_pkcs8(&CommonRng).unwrap().to_vec();
    let rak =
        Ed25519KeyPair::from_pkcs8(ekiden_common::untrusted::Input::from(&rak_pkcs8)).unwrap();

    // Prepare report data.
    let mut message = [0; 40];
    message[0..8].copy_from_slice(&HASH_CONTEXT);
    message[8..40].copy_from_slice(rak.public_key_bytes());
    let message_hash =
        ekiden_common::ring::digest::digest(&ekiden_common::ring::digest::SHA512_256, &message);
    let mut report_data = sgx_types::sgx_report_data_t::default();
    report_data.d[0..32].copy_from_slice(message_hash.as_ref());

    // Get public key and report for output.
    rak_pub.copy_from_slice(rak.public_key_bytes());
    *report = sgx_tse::rsgx_create_report(target_info, &report_data).expect("rsgx_create_report");

    // Move the key out to the global variable.
    {
        let mut guard = RAK.write().unwrap();
        if guard.is_some() {
            panic!("RAK already initialized");
        }
        *guard = Some(rak);
    }
}

pub fn sign_remote_attestation(ra: &[u8]) -> ekiden_common::ring::signature::Signature {
    RAK.read()
        .unwrap()
        .as_ref()
        .expect("RAK not initialized")
        .sign(ra)
}
