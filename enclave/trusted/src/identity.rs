#[cfg(target_env = "sgx")]
use sgx_tse;
#[cfg(target_env = "sgx")]
use sgx_tseal::SgxSealedData;
#[cfg(target_env = "sgx")]
use sgx_types;
#[cfg(target_env = "sgx")]
use sgx_types::{sgx_attributes_t, sgx_sealed_data_t};

#[cfg(target_env = "sgx")]
use protobuf;
use sodalite;

#[cfg(target_env = "sgx")]
use std;
#[cfg(not(target_env = "sgx"))]
use std::sync::Mutex as SgxMutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex;

use ekiden_common::random;
use ekiden_enclave_common;

use super::crypto::{SecretSeed, SECRET_SEED_LEN};

/// The format in which an identity is sealed an persisted.
#[cfg(target_env = "sgx")]
#[derive(Clone, Copy)]
struct IdentityExport {
    /// Seed for RPC `E` key.
    seed: SecretSeed,
}

#[cfg(target_env = "sgx")]
unsafe impl sgx_types::marker::ContiguousMemory for IdentityExport {}

#[derive(Clone)]
pub struct Identity {
    /// Public parts.
    pub public: ekiden_enclave_common::identity::PublicIdentityComponents,
    /// Long term enclave key E used in RPC, private part.
    pub rpc_key_e_priv: sodalite::BoxSecretKey,
}

lazy_static! {
    // Global cached identity.
    static ref IDENTITY: SgxMutex<Option<Identity>> = SgxMutex::new(None);
}

lazy_static! {
    // Global cached AV report.
    static ref AV_REPORT: SgxMutex<Option<ekiden_enclave_common::api::AvReport>> =
        SgxMutex::new(None);
}

/// ECALL, see edl
#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn identity_create(
    sealed_identity: *mut sgx_sealed_data_t,
    sealed_identity_capacity: usize,
    sealed_identity_length: &mut usize,
) {
    let mut export = IdentityExport {
        seed: [0; SECRET_SEED_LEN],
    };
    random::get_random_bytes(&mut export.seed).expect("ekiden_common::random::get_random_bytes");
    let sealed_data = SgxSealedData::<IdentityExport>::seal_data_ex(
        0x01, // KEYPOLICY_MRENCLAVE
        sgx_attributes_t {
            flags: 0xfffffffffffffff3,
            xfrm: 0,
        },
        0xF0000000,
        &[],
        &export,
    ).expect("SgxSealedData::seal_data_ex");
    let raw_data_len = SgxSealedData::<IdentityExport>::calc_raw_sealed_data_size(
        sealed_data.get_add_mac_txt_len(),
        sealed_data.get_encrypt_txt_len(),
    );
    if raw_data_len as usize > sealed_identity_capacity {
        panic!(
            "Sealed identity too large ({}/{})",
            raw_data_len, sealed_identity_capacity
        );
    }

    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_identity, raw_data_len);
    }
    *sealed_identity_length = raw_data_len as usize;
}

/// Get the public identity string.
fn get_public_identity() -> Vec<u8> {
    let guard = IDENTITY.lock().unwrap();
    let identity = guard.as_ref().expect("IDENTITY");
    ekiden_enclave_common::identity::pack_public_identity(&identity.public)
}

/// ECALL, see edl
#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn identity_restore(
    sealed_identity: *mut sgx_sealed_data_t,
    sealed_identity_length: usize,
    public_identity: *mut u8,
    public_identity_capacity: usize,
    public_identity_length: &mut usize,
) {
    let sealed_data = unsafe {
        SgxSealedData::<IdentityExport>::from_raw_sealed_data_t(
            sealed_identity,
            sealed_identity_length as u32,
        )
    }.expect("SgxSealedData::from_raw_sealed_data_t");
    let unsealed_data = sealed_data
        .unseal_data()
        .expect("SgxSealedData::unseal_data");
    let export = unsealed_data.get_decrypt_txt();

    let mut identity = Identity {
        public: ekiden_enclave_common::identity::PublicIdentityComponents {
            rpc_key_e_pub: [0; sodalite::BOX_PUBLIC_KEY_LEN],
        },
        rpc_key_e_priv: [0; sodalite::BOX_SECRET_KEY_LEN],
    };
    sodalite::box_keypair_seed(
        &mut identity.public.rpc_key_e_pub,
        &mut identity.rpc_key_e_priv,
        &export.seed,
    );

    {
        let mut guard = IDENTITY.lock().unwrap();
        // Abort if identity already initialized.
        if guard.is_some() {
            panic!("IDENTITY already initialized");
        }
        *guard = Some(identity);
    }

    let public_identity_src = get_public_identity();
    if public_identity_src.len() > public_identity_capacity {
        panic!(
            "Public identity string too large ({}/{})",
            public_identity_src.len(),
            public_identity_capacity
        );
    }
    let public_identity_dst =
        unsafe { std::slice::from_raw_parts_mut(public_identity, public_identity_src.len()) };
    public_identity_dst.copy_from_slice(&public_identity_src);
    *public_identity_length = public_identity_src.len();
}

/// For tests, generate an identity, cache that, generate a dummy AV report, and cache that.
#[cfg(not(target_env = "sgx"))]
pub fn nosgx_init_dummy() {
    let mut guard = IDENTITY.lock().unwrap();
    // Skip if identity already initialized.
    if guard.is_some() {
        return;
    }

    let mut seed: SecretSeed = [0; SECRET_SEED_LEN];
    random::get_random_bytes(&mut seed).expect("ekiden_common::random::get_random_bytes");

    let mut identity = Identity {
        public: ekiden_enclave_common::identity::PublicIdentityComponents {
            rpc_key_e_pub: [0; sodalite::BOX_PUBLIC_KEY_LEN],
        },
        rpc_key_e_priv: [0; sodalite::BOX_SECRET_KEY_LEN],
    };
    sodalite::box_keypair_seed(
        &mut identity.public.rpc_key_e_pub,
        &mut identity.rpc_key_e_priv,
        &seed,
    );
    *guard = Some(identity);

    let mut av_report = ekiden_enclave_common::api::AvReport::new();
    av_report.set_body(b"{}".to_vec());
    av_report.set_signature(vec![]);
    av_report.set_certificates(vec![]);

    {
        let mut guard = AV_REPORT.lock().unwrap();
        if guard.is_some() {
            panic!("AV_REPORT already initialized");
        }
        *guard = Some(av_report);
    }
}

/// ECALL, see edl
#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn identity_create_report(
    target_info: &sgx_types::sgx_target_info_t,
    report: &mut sgx_types::sgx_report_t,
) {
    let public_identity = get_public_identity();
    let report_data = ekiden_enclave_common::identity::pack_report_data(&public_identity);
    *report = sgx_tse::rsgx_create_report(target_info, &report_data).expect("rsgx_create_report");
}

/// ECALL, see edl
#[cfg(target_env = "sgx")]
#[no_mangle]
pub extern "C" fn identity_set_av_report(av_report: *const u8, av_report_length: usize) {
    let av_report_slice = unsafe { std::slice::from_raw_parts(av_report, av_report_length) };
    let av_report =
        protobuf::parse_from_bytes(av_report_slice).expect("protobuf::parse_from_bytes av_report");
    {
        let mut guard = AV_REPORT.lock().unwrap();
        if guard.is_some() {
            panic!("AV_REPORT already initialized");
        }
        *guard = Some(av_report);
    }
}

/// Get a copy of the identity.
pub fn get_identity() -> Identity {
    IDENTITY
        .lock()
        .unwrap()
        .as_ref()
        .expect("IDENTITY not initialized")
        .clone()
}

/// Get the identity proof.
pub fn get_proof() -> ekiden_enclave_common::api::IdentityProof {
    let mut identity_proof = ekiden_enclave_common::api::IdentityProof::new();
    identity_proof.set_public_identity(get_public_identity());
    identity_proof.set_av_report(
        AV_REPORT
            .lock()
            .unwrap()
            .as_ref()
            .expect("AV_REPORT not initialized")
            .clone(),
    );
    identity_proof
}
