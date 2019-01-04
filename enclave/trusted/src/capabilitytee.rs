//! Functionality for implementing RFC 0009 CapabilityTEE.

#[cfg(target_env = "sgx")]
use sgx_tse;
#[cfg(target_env = "sgx")]
use sgx_types;

#[cfg(not(target_env = "sgx"))]
use std::sync::RwLock as SgxRwLock;
#[cfg(target_env = "sgx")]
use std::sync::SgxRwLock;

use sodalite;

const HASH_CONTEXT: [u8; 8] = *b"EkNodReg";

lazy_static! {
    // Global runtime attestation key.
    static ref RAK: SgxRwLock<Option<(sodalite::SignPublicKey, sodalite::SignSecretKey)>> =
        SgxRwLock::new(None);
}

#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn capabilitytee_init(
    rak_pub: &mut [u8; 32],
    target_info: &sgx_types::sgx_target_info_t,
    report: &mut sgx_types::sgx_report_t,
) {
    // Generate new runtime attestation private key.
    let mut seed = [0; 32];
    ekiden_common::random::get_random_bytes(&mut seed)
        .expect("ekiden_common::random::get_random_bytes");
    // Extra-defensive: our own local space for the public key, in case someday the output becomes user_check.
    let mut rak_pub_local = [0; sodalite::SIGN_PUBLIC_KEY_LEN];
    let mut rak_priv = [0; sodalite::SIGN_SECRET_KEY_LEN];
    sodalite::sign_keypair_seed(&mut rak_pub_local, &mut rak_priv, &seed);

    // Prepare report data.
    let mut message = [0; 40];
    message[0..8].copy_from_slice(&HASH_CONTEXT);
    message[8..40].copy_from_slice(&rak_pub_local);
    let mut message_hash = [0; sodalite::HASH_LEN];
    sodalite::hash(&mut message_hash, &message);
    let mut report_data = sgx_types::sgx_report_data_t::default();
    report_data.d.copy_from_slice(&message_hash);

    // Get public key and report for output.
    rak_pub.copy_from_slice(&rak_pub_local);
    *report = sgx_tse::rsgx_create_report(target_info, &report_data).expect("rsgx_create_report");

    // Move the key out to the global variable.
    {
        let mut guard = RAK.write().unwrap();
        if guard.is_some() {
            panic!("RAK already initialized");
        }
        *guard = Some((rak_pub_local, rak_priv));
    }
}

pub fn sign_remote_attestation(ra: &[u8]) -> Vec<u8> {
    let smlen = ra.len() + sodalite::SIGN_LEN;
    let mut sm = vec![0; smlen];
    let guard = RAK.read().unwrap();
    let (_rak_pub, rak_priv) = guard.as_ref().expect("RAK not initialized");
    sodalite::sign_attached(&mut sm, ra, rak_priv);
    sm
}
