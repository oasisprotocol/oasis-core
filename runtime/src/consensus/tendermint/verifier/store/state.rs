use io_context::Context;
use std::sync::Arc;

use sgx_isa::Keypolicy;
use tendermint_light_client::types::LightBlock as TMLightBlock;

use crate::{
    common::{
        namespace::Namespace,
        sgx::{seal, EnclaveIdentity},
    },
    consensus::{
        tendermint::{encode_light_block, LightBlockMeta},
        verifier::{Error, TrustRoot, TrustedState},
    },
    protocol::ProtocolUntrustedLocalStorage,
    storage::KeyValue,
    Protocol,
};

/// Storage key prefix under which the sealed trusted state is stored in
/// the untrusted local storage.
///
/// The actual key includes the MRENCLAVE to support upgrades.
const TRUSTED_STATE_STORAGE_KEY_PREFIX: &str = "tendermint.verifier.trusted_state";

/// Domain separation context for the trusted state.
const TRUSTED_STATE_CONTEXT: &[u8] = b"oasis-core/verifier: trusted state";

/// Untrusted local storage for storing the sealed latest trusted root.
pub struct TrustedStateStore {
    runtime_id: Namespace,
    chain_context: String,
    untrusted_local_store: ProtocolUntrustedLocalStorage,
}

impl TrustedStateStore {
    /// Create a new trusted state local store.
    pub fn new(runtime_id: Namespace, chain_context: String, protocol: Arc<Protocol>) -> Self {
        let untrusted_local_store =
            ProtocolUntrustedLocalStorage::new(Context::background(), protocol);

        Self {
            runtime_id,
            chain_context,
            untrusted_local_store,
        }
    }

    pub fn save(&self, trusted_block: &TMLightBlock) {
        // Build trusted state.
        let trust_root = TrustRoot {
            height: trusted_block.height().into(),
            hash: trusted_block.signed_header.header.hash().to_string(),
            runtime_id: self.runtime_id,
            chain_context: self.chain_context.clone(),
        };
        let lbm = LightBlockMeta {
            signed_header: Some(trusted_block.signed_header.clone()),
            validators: trusted_block.validators.clone(),
        };
        let trusted_block = Some(encode_light_block(&lbm).unwrap());
        let trusted_state = TrustedState {
            trust_root,
            trusted_block,
        };

        // Serialize and seal the trusted state.
        let raw = cbor::to_vec(trusted_state);
        let sealed = seal::seal(Keypolicy::MRENCLAVE, TRUSTED_STATE_CONTEXT, &raw);

        // Store the trusted state.
        self.untrusted_local_store
            .insert(Self::derive_storage_key(), sealed)
            .unwrap();
    }

    pub fn load(&self, trust_root: &TrustRoot) -> Result<TrustedState, Error> {
        // Attempt to load the previously sealed trusted state.
        let untrusted_value = self
            .untrusted_local_store
            .get(Self::derive_storage_key())
            .map_err(|_| Error::TrustedStateLoadingFailed)?;
        if untrusted_value.is_empty() {
            return Ok(TrustedState {
                trust_root: trust_root.clone(),
                trusted_block: None,
            });
        }

        // Unseal the sealed trusted state.
        let raw = seal::unseal(
            Keypolicy::MRENCLAVE,
            TRUSTED_STATE_CONTEXT,
            &untrusted_value,
        )
        .unwrap();
        let trusted_state: TrustedState =
            cbor::from_slice(&raw).expect("corrupted sealed trusted state");

        Ok(trusted_state)
    }

    fn derive_storage_key() -> Vec<u8> {
        // Namespace storage key by MRENCLAVE as we can only unseal our own sealed data and we need
        // to support upgrades. We assume that an upgrade will include an up-to-date trusted state
        // anyway.
        format!(
            "{}.{:x}",
            TRUSTED_STATE_STORAGE_KEY_PREFIX,
            EnclaveIdentity::current()
                .map(|eid| eid.mr_enclave)
                .unwrap_or_default()
        )
        .into_bytes()
    }
}
