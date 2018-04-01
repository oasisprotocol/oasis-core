use sgx_types;

use sodalite;

/// Used in enclave identity proof.
const QUOTE_CONTEXT_IDENTITY: super::quote::QuoteContext = *b"EkQ-Iden";

/// Version of the public identity string format.
const IDENTITY_VERSION: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

/// The components of a public identity string.
#[derive(Clone)]
pub struct PublicIdentityComponents {
    /// Long term enclave key E used in RPC, public part.
    pub rpc_key_e_pub: sodalite::BoxPublicKey,
}

/// Pack components into a public identity string.
pub fn pack_public_identity(components: &PublicIdentityComponents) -> Vec<u8> {
    components.rpc_key_e_pub.to_vec()
}

/// Unpack components from a public identity string.
pub fn unpack_public_identity(public_identity: &[u8]) -> PublicIdentityComponents {
    let mut components = PublicIdentityComponents {
        rpc_key_e_pub: [0; sodalite::BOX_PUBLIC_KEY_LEN],
    };
    components.rpc_key_e_pub.copy_from_slice(public_identity);
    components
}

/// Pack fields into a report data struct.
pub fn pack_report_data(public_identity: &[u8]) -> sgx_types::sgx_report_data_t {
    let mut hash = [0; sodalite::HASH_LEN];
    sodalite::hash(&mut hash, public_identity);
    let mut report_data = sgx_types::sgx_report_data_t::default();
    report_data.d[0..8].copy_from_slice(&QUOTE_CONTEXT_IDENTITY);
    report_data.d[8..16].copy_from_slice(&IDENTITY_VERSION);
    // [16..32] is left zeroed
    report_data.d[32..64].copy_from_slice(&hash[..32]);
    report_data
}
