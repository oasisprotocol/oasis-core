use std::sync::Arc;

use sgx_isa::Keypolicy;
use tendermint_light_client::{
    store::LightStore,
    types::{LightBlock as TMLightBlock, Status},
};

use crate::{
    common::{
        namespace::Namespace,
        sgx::{seal, EnclaveIdentity},
    },
    consensus::verifier::{Error, TrustRoot},
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

/// An encoded Tendermint light block.
#[derive(Debug, Clone)]
pub struct EncodedLightBlock(TMLightBlock);

impl From<TMLightBlock> for EncodedLightBlock {
    fn from(value: TMLightBlock) -> Self {
        Self(value)
    }
}

impl From<EncodedLightBlock> for TMLightBlock {
    fn from(value: EncodedLightBlock) -> Self {
        value.0
    }
}

impl cbor::Encode for EncodedLightBlock {
    fn into_cbor_value(self) -> cbor::Value {
        cbor::serde::to_value(&self.0).unwrap()
    }
}

impl cbor::Decode for EncodedLightBlock {
    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        cbor::serde::from_value(value)
            .map_err(|_| cbor::DecodeError::ParsingFailed)
            .map(Self)
    }
}

/// Trusted state containing trust root and trusted light block.
#[derive(Debug, Clone, Default, cbor::Encode, cbor::Decode)]
pub struct TrustedState {
    /// Trust root.
    pub trust_root: TrustRoot,
    /// Trusted light blocks, ordered by height from lowest to highest.
    ///
    /// Optional as we don't want to force trusted state for embedded trust
    /// root to have a matching trusted light block.
    pub trusted_blocks: Vec<EncodedLightBlock>,
}

/// Untrusted local storage for storing the sealed latest trusted root.
pub struct TrustedStateStore {
    runtime_id: Namespace,
    chain_context: String,
    untrusted_local_store: ProtocolUntrustedLocalStorage,
}

impl TrustedStateStore {
    /// Create a new trusted state local store.
    pub fn new(runtime_id: Namespace, chain_context: String, protocol: Arc<Protocol>) -> Self {
        let untrusted_local_store = ProtocolUntrustedLocalStorage::new(protocol);

        Self {
            runtime_id,
            chain_context,
            untrusted_local_store,
        }
    }

    /// Persist latest trusted state from the in-memory light store.
    ///
    /// # Panics
    ///
    /// Panics in case the light store does not have any blocks or if insertion to the underlying
    /// runtime's untrusted local store fails.
    pub fn save(&self, store: &Box<dyn LightStore>) {
        let lowest_block = store.lowest(Status::Trusted).unwrap();
        let highest_block = store.highest(Status::Trusted).unwrap();

        // Generate a new trust root from the highest trusted block.
        let trust_root = TrustRoot {
            height: highest_block.height().into(),
            hash: highest_block.signed_header.header.hash().to_string(),
            runtime_id: self.runtime_id,
            chain_context: self.chain_context.clone(),
        };

        let trusted_state = TrustedState {
            trust_root,
            trusted_blocks: vec![lowest_block.into(), highest_block.into()],
        };

        // Serialize and seal the trusted state.
        let raw = cbor::to_vec(trusted_state);
        let sealed = seal::seal(Keypolicy::MRENCLAVE, TRUSTED_STATE_CONTEXT, &raw);

        // Store the trusted state.
        self.untrusted_local_store
            .insert(Self::derive_storage_key(), sealed)
            .unwrap();
    }

    /// Attempts to load previously sealed trusted state.
    ///
    /// If no sealed trusted state is available, it returns state based on the passed trust root.
    pub fn load(&self, trust_root: &TrustRoot) -> Result<TrustedState, Error> {
        // Attempt to load the previously sealed trusted state.
        let untrusted_value = self
            .untrusted_local_store
            .get(Self::derive_storage_key())
            .map_err(|_| Error::TrustedStateLoadingFailed)?;
        if untrusted_value.is_empty() {
            return Ok(TrustedState {
                trust_root: trust_root.clone(),
                trusted_blocks: vec![],
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
