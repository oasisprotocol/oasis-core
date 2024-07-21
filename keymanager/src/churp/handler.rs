//! CHURP handler.
use std::{
    cmp,
    collections::HashMap,
    convert::TryInto,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;
use sp800_185::KMac;

use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signer},
        },
        namespace::Namespace,
        sgx::EnclaveIdentity,
    },
    consensus::{
        beacon::EpochTime,
        keymanager::churp::{SignedPolicySGX, Status, SuiteId},
        verifier::Verifier,
    },
    enclave_rpc::Context as RpcContext,
    future::block_on,
    identity::Identity,
    protocol::ProtocolUntrustedLocalStorage,
    Protocol,
};

use secret_sharing::{
    churp::{encode_shareholder, Dealer, Handoff, HandoffKind, Shareholder, VerifiableSecretShare},
    kdc::KeySharer,
    poly::{scalar_from_bytes, scalar_to_bytes},
    suites::{p384, Suite},
    vss::VerificationMatrix,
};

use crate::{
    beacon::State as BeaconState,
    client::{KeyManagerClient, RemoteClient},
    registry::State as RegistryState,
};

use super::{
    storage::Storage, ApplicationRequest, ConfirmationRequest, EncodedEncryptedPoint,
    EncodedVerifiableSecretShare, Error, FetchRequest, FetchResponse, HandoffRequest,
    KeyShareRequest, QueryRequest, SignedApplicationRequest, SignedConfirmationRequest,
    State as ChurpState, VerifiedPolicies,
};

/// A handoff interval that disables handoffs.
pub const HANDOFFS_DISABLED: EpochTime = 0xffffffffffffffff;

/// Signature context for signing application requests.
const APPLICATION_REQUEST_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: application request";

/// Signature context for signing confirmation requests.
const CONFIRMATION_REQUEST_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: confirmation request";

/// Custom KMAC domain separation for checksums of verification matrices.
const CHECKSUM_VERIFICATION_MATRIX_CUSTOM: &[u8] =
    b"oasis-core/keymanager/churp: verification matrix";

/// Domain separation tag for encoding shareholder identifiers.
const ENCODE_SHAREHOLDER_CONTEXT: &[u8] = b"oasis-core/keymanager/churp: encode shareholder";

/// Domain separation tag for encoding key identifiers for key share derivation
/// approved by an SGX policy.
///
/// SGX policies specify which enclave identities are authorized to access
/// runtime key shares.
const ENCODE_SGX_POLICY_KEY_ID_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: encode SGX policy key ID";

/// Domain separation tag for encoding key identifiers for key share derivation
/// approved by a custom policy.
///
/// Custom policies allow access to key shares only for clients that submit
/// a proof, which can be validated against the policy. The hash of the policy
/// is part of the key identifier and is integral to the key derivation process.
#[allow(dead_code)]
const ENCODE_CUSTOM_POLICY_KEY_ID_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: encode custom policy key ID";

/// The runtime separator used to add additional domain separation based
/// on the runtime ID.
const RUNTIME_CONTEXT_SEPARATOR: &[u8] = b" for runtime ";

/// The churp separator used to add additional domain separation based
/// on the churp ID.
const CHURP_CONTEXT_SEPARATOR: &[u8] = b" for churp ";

/// Represents information about a dealer.
struct DealerInfo<G: Group + GroupEncoding> {
    /// The epoch during which this dealer is active.
    epoch: EpochTime,
    /// The dealer associated with this information.
    dealer: Arc<Dealer<G>>,
}

/// Represents information about a handoff.
struct HandoffInfo<G: Group + GroupEncoding> {
    /// The handoff epoch.
    epoch: EpochTime,
    /// The handoff associated with this information.
    handoff: Arc<Handoff<G>>,
}

pub(crate) trait Handler {
    /// Returns the verification matrix of the shared secret bivariate
    /// polynomial from the last successfully completed handoff.
    ///
    /// The verification matrix is a matrix of dimensions t_n x t_m, where
    /// t_n = threshold and t_m = 2 * threshold + 1. It contains encrypted
    /// coefficients of the secret bivariate polynomial whose zero coefficient
    /// represents the shared secret.
    ///
    /// Verification matrix:
    /// ```text
    ///     M = [b_{i,j} * G]
    /// ```
    /// Bivariate polynomial:
    /// ```text
    ///     B(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    /// ```
    /// Shared secret:
    /// ```text
    ///     Secret = B(0, 0)
    /// ```
    ///
    /// This matrix is used to verify switch points derived from the bivariate
    /// polynomial share in handoffs.
    ///
    /// NOTE: This method can be called over an insecure channel, as the matrix
    /// does not contain any sensitive information. However, the checksum
    /// of the matrix should always be verified against the consensus layer.
    fn verification_matrix(&self, req: &QueryRequest) -> Result<Vec<u8>>;

    /// Returns switch point for share reduction for the calling node.
    ///
    /// The point is evaluation of the shared secret bivariate polynomial
    /// at the given x (me) and y value (node ID).
    ///
    /// Switch point:
    /// ```text
    ///     Point = B(me, node_id)
    /// ```
    /// Bivariate polynomial:
    /// ```text
    ///     B(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    /// ```
    ///
    /// WARNING: This method must be called over a secure channel as the point
    /// needs to be kept secret and generated only for authorized nodes.
    fn share_reduction_switch_point(&self, ctx: &RpcContext, req: &QueryRequest)
        -> Result<Vec<u8>>;

    /// Returns switch point for full share distribution for the calling node.
    ///
    /// The point is evaluation of the proactivized shared secret bivariate
    /// polynomial at the given x (node ID) and y value (me).
    ///
    /// Switch point:
    /// ```text
    ///     Point = B(node_id, me) + \sum Q_i(node_id, me)
    /// ```
    /// Bivariate polynomial:
    /// ```text
    ///     B(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    /// ```
    /// Proactive bivariate polynomial:
    /// ```text
    ///     Q_i(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    /// ```
    ///
    /// WARNING: This method must be called over a secure channel as the point
    /// needs to be kept secret and generated only for authorized nodes.
    fn share_distribution_switch_point(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>>;

    /// Returns proactive bivariate polynomial share for the calling node.
    ///
    /// A bivariate share is a partial evaluation of a randomly selected
    /// bivariate polynomial at a specified x or y value (node ID). Each node
    /// interested in joining the new committee selects a bivariate polynomial
    /// before the next handoff and commits to it by submitting the checksum
    /// of the corresponding verification matrix to the consensus layer.
    /// The latter can be used to verify the received bivariate shares.
    ///
    /// Bivariate polynomial share:
    /// ```text
    ///     S_i(y) = Q_i(node_id, y) (dealing phase or unchanged committee)
    ///     S_i(x) = Q_i(x, node_id) (committee changes)
    /// ```
    /// Proactive bivariate polynomial:
    /// ```text
    ///     Q_i(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    /// ```
    ///
    /// WARNING: This method must be called over a secure channel as
    /// the polynomial needs to be kept secret and generated only
    /// for authorized nodes.
    fn bivariate_share(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<EncodedVerifiableSecretShare>;

    /// Returns the key share for the given key ID generated by the key
    /// derivation center.
    ///
    /// Key share:
    /// ```text
    ///     KS_i = s_i * H(key_id)
    /// ```
    ///
    /// WARNING: This method must be called over a secure channel as the key
    /// share needs to be kept secret and generated only for authorized nodes.
    fn sgx_policy_key_share(
        &self,
        ctx: &RpcContext,
        req: &KeyShareRequest,
    ) -> Result<EncodedEncryptedPoint>;

    /// Prepare CHURP for participation in the given handoff of the protocol.
    ///
    /// Initialization randomly selects a bivariate polynomial for the given
    /// handoff, computes the corresponding verification matrix and its
    /// checksum, and signs the latter.
    ///
    /// Bivariate polynomial:
    ///     B(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    ///
    /// Verification matrix:
    ///     M = [b_{i,j} * G]
    ///
    /// Checksum:
    ///     H = KMAC256(M, runtime ID, handoff)
    ///
    /// The bivariate polynomial is zero-hole in all handoffs expect in the
    /// first one (dealing phase).
    ///
    /// This method must be called locally.
    fn apply(&self, req: &HandoffRequest) -> Result<SignedApplicationRequest>;

    /// Tries to fetch switch points for share reduction from the given nodes.
    ///
    /// Switch points should be obtained from (at least) t distinct nodes
    /// belonging to the old committee, verified against verification matrix
    /// whose checksum was published in the consensus layer, merged into
    /// a reduced share using Lagrange interpolation and proactivized with
    /// bivariate shares.
    ///
    /// Switch point:
    /// ```text
    ///     P_i = B(node_i, me)
    ///```
    /// Reduced share:
    /// ```text
    ///     RS(x) = B(x, me)
    /// ````
    /// Proactive reduced share:
    /// ```text
    ///     QR(x) = RS(x) + \sum Q_i(x, me)
    /// ````
    fn share_reduction(&self, req: &FetchRequest) -> Result<FetchResponse>;

    /// Tries to fetch switch data points for full share distribution from
    /// the given nodes.
    ///
    /// Switch points should be obtained from (at least) 2t distinct nodes
    /// belonging to the new committee, verified against the sum of the
    /// verification matrix and the verification matrices of proactive
    /// bivariate shares, whose checksums were published in the consensus
    /// layer, and merged into a full share using Lagrange interpolation.
    ///
    /// Switch point:
    /// ```text
    ///     P_i = B(me, node_i) + \sum Q_i(me, node_i)
    ///```
    /// Full share:
    /// ```text
    ///     FS(x) = B(me, y) + \sum Q_i(me, y) = B'(me, y)
    /// ````
    fn share_distribution(&self, req: &FetchRequest) -> Result<FetchResponse>;

    /// Tries to fetch proactive bivariate shares from the given nodes.
    ///
    /// Bivariate shares should be fetched from all candidates for the new
    /// committee, including our own, verified against verification matrices
    /// whose checksums were published in the consensus layer, and summed
    /// into a bivariate polynomial.
    ///
    /// Bivariate polynomial share:
    /// ```text
    ///     S_i(y) = Q_i(me, y) (dealing phase or unchanged committee)
    ///     S_i(x) = Q_i(x, me) (committee changes)
    /// ```
    fn proactivization(&self, req: &FetchRequest) -> Result<FetchResponse>;

    /// Returns a signed confirmation request containing the checksum
    /// of the merged verification matrix.
    fn confirmation(&self, req: &HandoffRequest) -> Result<SignedConfirmationRequest>;

    /// Finalizes the specified scheme by cleaning up obsolete dealers,
    /// handoffs, and shareholders. If the handoff was just completed,
    /// the shareholder is made available, and its share is persisted
    /// to the local storage.
    fn finalize(&self, req: &HandoffRequest) -> Result<()>;
}

/// Key manager application that implements churn-robust proactive secret
/// sharing scheme (CHURP).
pub struct Churp {
    /// Host node identifier.
    node_id: PublicKey,
    /// Key manager runtime ID.
    runtime_id: Namespace,
    /// Runtime identity.
    identity: Arc<Identity>,
    /// Low-level access to the underlying Runtime Host Protocol.
    protocol: Arc<Protocol>,
    /// Consensus verifier.
    consensus_verifier: Arc<dyn Verifier>,
    /// Verified churp state.
    churp_state: ChurpState,

    /// Cached instances.
    instances: Mutex<HashMap<u8, Arc<dyn Handler + Send + Sync>>>,
    /// Cached verified policies.
    policies: Arc<VerifiedPolicies>,
}

impl Churp {
    pub fn new(
        node_id: PublicKey,
        identity: Arc<Identity>,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
    ) -> Self {
        let runtime_id = protocol.get_runtime_id();
        let churp_state = ChurpState::new(consensus_verifier.clone());
        let instances = Mutex::new(HashMap::new());
        let policies = Arc::new(VerifiedPolicies::new());

        Self {
            node_id,
            runtime_id,
            identity,
            protocol,
            consensus_verifier,
            churp_state,
            instances,
            policies,
        }
    }

    fn get_instance(
        &self,
        churp_id: u8,
        runtime_id: Namespace,
    ) -> Result<Arc<dyn Handler + Send + Sync>> {
        // Ensure runtime_id matches.
        if self.runtime_id != runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }

        // Return the instance if it exists.
        let mut instances = self.instances.lock().unwrap();
        if let Some(instance) = instances.get(&churp_id) {
            return Ok(instance.clone());
        }

        // Create a new instance based on the suite type.
        let status = self.churp_state.status(self.runtime_id, churp_id)?;
        let instance = match status.suite_id {
            SuiteId::NistP384Sha3_384 => Instance::<p384::Sha3_384>::new(
                churp_id,
                self.node_id,
                self.identity.clone(),
                self.protocol.clone(),
                self.consensus_verifier.clone(),
                self.policies.clone(),
            ),
        };

        // Load secret shares and bivariate share.
        instance.init(&status)?;

        // Store the new instance.
        let instance = Arc::new(instance);
        instances.insert(churp_id, instance.clone());

        Ok(instance)
    }
}

impl Handler for Churp {
    fn verification_matrix(&self, req: &QueryRequest) -> Result<Vec<u8>> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.verification_matrix(req)
    }

    fn share_reduction_switch_point(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.share_reduction_switch_point(ctx, req)
    }

    fn share_distribution_switch_point(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.share_distribution_switch_point(ctx, req)
    }

    fn bivariate_share(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<EncodedVerifiableSecretShare> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.bivariate_share(ctx, req)
    }

    fn sgx_policy_key_share(
        &self,
        ctx: &RpcContext,
        req: &KeyShareRequest,
    ) -> Result<EncodedEncryptedPoint> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.sgx_policy_key_share(ctx, req)
    }

    fn apply(&self, req: &HandoffRequest) -> Result<SignedApplicationRequest> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.apply(req)
    }

    fn share_reduction(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.share_reduction(req)
    }

    fn share_distribution(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.share_distribution(req)
    }

    fn proactivization(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.proactivization(req)
    }

    fn confirmation(&self, req: &HandoffRequest) -> Result<SignedConfirmationRequest> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.confirmation(req)
    }

    fn finalize(&self, req: &HandoffRequest) -> Result<()> {
        let instance = self.get_instance(req.id, req.runtime_id)?;
        instance.finalize(req)
    }
}

struct Instance<S: Suite> {
    /// Host node identifier.
    node_id: PublicKey,
    /// Instance identifier.
    churp_id: u8,
    /// Key manager runtime ID.
    runtime_id: Namespace,
    /// Runtime identity.
    identity: Arc<Identity>,
    /// Runtime attestation key signer.
    signer: Arc<dyn Signer>,

    /// Storage handler.
    storage: Storage,
    /// Consensus verifier.
    consensus_verifier: Arc<dyn Verifier>,
    /// Low-level access to the underlying Runtime Host Protocol.
    protocol: Arc<Protocol>,

    /// Verified beacon state.
    beacon_state: BeaconState,
    /// Verified churp state.
    churp_state: ChurpState,
    /// Verified registry state.
    registry_state: RegistryState,

    /// Shareholders with secret shares for completed handoffs.
    ///
    /// The map may also contain shareholders for failed or unfinished
    /// handoffs, so always verify if the handoff succeeded in the consensus.
    shareholders: Mutex<HashMap<EpochTime, Arc<Shareholder<S::Group>>>>,
    /// Dealer of bivariate shares for the next handoff.
    dealer: Mutex<Option<DealerInfo<S::Group>>>,
    /// Next handoff.
    handoff: Mutex<Option<HandoffInfo<S::Group>>>,

    /// Cached verified policies.
    policies: Arc<VerifiedPolicies>,

    /// Domain separation tag for encoding shareholder identifiers.
    shareholder_dst: Vec<u8>,
    /// Domain separation tag for encoding key identifiers for key share
    /// derivation approved by an SGX policy.
    sgx_policy_key_id_dst: Vec<u8>,
}

impl<S: Suite> Instance<S> {
    /// Creates a new CHURP instance.
    pub fn new(
        churp_id: u8,
        node_id: PublicKey,
        identity: Arc<Identity>,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
        policies: Arc<VerifiedPolicies>,
    ) -> Self {
        let runtime_id = protocol.get_runtime_id();
        let storage = Storage::new(Arc::new(ProtocolUntrustedLocalStorage::new(
            protocol.clone(),
        )));
        let signer: Arc<dyn Signer> = identity.clone();

        let beacon_state = BeaconState::new(consensus_verifier.clone());
        let churp_state = ChurpState::new(consensus_verifier.clone());
        let registry_state = RegistryState::new(consensus_verifier.clone());

        let shareholders = Mutex::new(HashMap::new());
        let dealer = Mutex::new(None);
        let handoff = Mutex::new(None);

        let shareholder_dst =
            Self::domain_separation_tag(ENCODE_SHAREHOLDER_CONTEXT, &runtime_id, churp_id);
        let sgx_policy_key_id_dst =
            Self::domain_separation_tag(ENCODE_SGX_POLICY_KEY_ID_CONTEXT, &runtime_id, churp_id);

        Self {
            churp_id,
            identity,
            signer,
            node_id,
            runtime_id,
            protocol,
            consensus_verifier,
            storage,
            beacon_state,
            shareholders,
            churp_state,
            registry_state,
            dealer,
            handoff,
            policies,
            shareholder_dst,
            sgx_policy_key_id_dst,
        }
    }

    /// Initializes the instance by loading the shareholder for the last
    /// successfully completed handoff, as well as the shareholder and
    /// the dealer for the upcoming handoff, if they are available.
    pub fn init(&self, status: &Status) -> Result<()> {
        let checksum = status
            .applications
            .get(&self.node_id)
            .map(|app| app.checksum);

        self.load_shareholder(status.handoff)?;
        self.load_next_shareholder(status.next_handoff)?;
        self.load_dealer(status.next_handoff, checksum)
    }

    /// Tries to fetch switch point for share reduction from the given node.
    pub fn fetch_share_reduction_switch_point(
        &self,
        node_id: PublicKey,
        status: &Status,
        handoff: &Handoff<S::Group>,
        client: &RemoteClient,
    ) -> Result<bool> {
        let x = encode_shareholder::<S>(&node_id.0, &self.shareholder_dst)?;

        if !handoff.needs_share_reduction_switch_point(&x)? {
            return Err(Error::InvalidShareholder.into());
        }

        // Fetch from the host node.
        if node_id == self.node_id {
            let shareholder = self.get_shareholder(status.handoff)?;
            let point = shareholder.switch_point(&x);

            if handoff.needs_verification_matrix()? {
                // Local verification matrix is trusted.
                let vm = shareholder.verifiable_share().verification_matrix().clone();
                handoff.set_verification_matrix(vm)?;
            }

            return handoff.add_share_reduction_switch_point(x, point);
        }

        // Fetch from the remote node.
        client.set_nodes(vec![node_id]);

        if handoff.needs_verification_matrix()? {
            // The remote verification matrix needs to be verified.
            let vm = block_on(client.churp_verification_matrix(self.churp_id, status.handoff))?;
            let checksum = self.checksum_verification_matrix_bytes(&vm, status.handoff);
            let status_checksum = status.checksum.ok_or(Error::InvalidHandoff)?; // Should never happen.
            if checksum != status_checksum {
                return Err(Error::InvalidVerificationMatrixChecksum.into());
            }

            let vm = VerificationMatrix::from_bytes(&vm)
                .ok_or(Error::VerificationMatrixDecodingFailed)?;
            handoff.set_verification_matrix(vm)?;
        }

        let point = block_on(client.churp_share_reduction_point(
            self.churp_id,
            status.next_handoff,
            self.node_id,
        ))?;
        let point = scalar_from_bytes(&point).ok_or(Error::PointDecodingFailed)?;

        handoff.add_share_reduction_switch_point(x, point)
    }

    /// Tries to fetch switch point for share reduction from the given node.
    pub fn fetch_share_distribution_switch_point(
        &self,
        node_id: PublicKey,
        status: &Status,
        handoff: &Handoff<S::Group>,
        client: &RemoteClient,
    ) -> Result<bool> {
        let x = encode_shareholder::<S>(&node_id.0, &self.shareholder_dst)?;

        if !handoff.needs_full_share_distribution_switch_point(&x)? {
            return Err(Error::InvalidShareholder.into());
        }

        // Fetch from the host node.
        if node_id == self.node_id {
            let shareholder = handoff.get_reduced_shareholder()?;
            let point = shareholder.switch_point(&x);

            return handoff.add_full_share_distribution_switch_point(x, point);
        }

        // Fetch from the remote node.
        client.set_nodes(vec![node_id]);
        let point = block_on(client.churp_share_distribution_point(
            self.churp_id,
            status.next_handoff,
            self.node_id,
        ))?;
        let point = scalar_from_bytes(&point).ok_or(Error::PointDecodingFailed)?;

        handoff.add_full_share_distribution_switch_point(x, point)
    }

    /// Tries to fetch proactive bivariate share from the given node.
    pub fn fetch_bivariate_share(
        &self,
        node_id: PublicKey,
        status: &Status,
        handoff: &Handoff<S::Group>,
        client: &RemoteClient,
    ) -> Result<bool> {
        let x = encode_shareholder::<S>(&node_id.0, &self.shareholder_dst)?;

        if !handoff.needs_bivariate_share(&x)? {
            return Err(Error::InvalidShareholder.into());
        }

        // Fetch from the host node.
        if node_id == self.node_id {
            let kind = Self::handoff_kind(status);
            let dealer = self.get_dealer(status.next_handoff)?;
            let share = dealer.make_share(x, kind);
            let vm = dealer.verification_matrix().clone();
            let verifiable_share = VerifiableSecretShare::new(share, vm);

            return handoff.add_bivariate_share(&x, verifiable_share);
        }

        // Fetch from the remote node.
        client.set_nodes(vec![node_id]);
        let share = block_on(client.churp_bivariate_share(
            self.churp_id,
            status.next_handoff,
            self.node_id,
        ))?;

        // The remote verification matrix needs to be verified.
        let checksum = self
            .checksum_verification_matrix_bytes(&share.verification_matrix, status.next_handoff);
        let application = status
            .applications
            .get(&node_id)
            .ok_or(Error::InvalidShareholder)?; // Should never happen, as we verify if we require this share.

        if checksum != application.checksum {
            return Err(Error::InvalidVerificationMatrixChecksum.into());
        }

        let verifiable_share: VerifiableSecretShare<S::Group> = share.try_into()?;

        handoff.add_bivariate_share(&x, verifiable_share)
    }

    /// Returns the shareholder for the given epoch.
    fn get_shareholder(&self, epoch: EpochTime) -> Result<Arc<Shareholder<S::Group>>> {
        let shareholders = self.shareholders.lock().unwrap();
        shareholders
            .get(&epoch)
            .cloned()
            .ok_or(Error::ShareholderNotFound.into())
    }

    /// Adds a shareholder for the given epoch.
    fn add_shareholder(&self, shareholder: Arc<Shareholder<S::Group>>, epoch: EpochTime) {
        let mut shareholders = self.shareholders.lock().unwrap();
        shareholders.insert(epoch, shareholder);
    }

    /// Keeps only the shareholders that belong to one of the given epochs.
    fn keep_shareholders(&self, epochs: &[EpochTime]) {
        let mut shareholders = self.shareholders.lock().unwrap();
        shareholders.retain(|epoch, _| epochs.contains(epoch));
    }

    /// Loads the shareholder from local storage for the given epoch.
    fn load_shareholder(&self, epoch: EpochTime) -> Result<()> {
        // Skip if no handoffs have been completed so far.
        if epoch == 0 {
            return Ok(());
        }

        let share = self
            .storage
            .load_secret_share(self.churp_id, epoch)
            .or_else(|err| ignore_error(err, Error::InvalidSecretShare))?; // Ignore previous shares.

        // If the secret share is not available, check if the next handoff
        // succeeded as it might have been confirmed while we were away.
        let share = match share {
            Some(share) => Some(share),
            None => {
                let share = self
                    .storage
                    .load_next_secret_share(self.churp_id, epoch)
                    .or_else(|err| ignore_error(err, Error::InvalidSecretShare))?; // Ignore previous shares.

                // // Back up the secret share, if it is valid.
                if let Some(share) = share.as_ref() {
                    self.storage
                        .store_secret_share(share, self.churp_id, epoch)?;
                }

                share
            }
        };

        self.verify_and_add_shareholder(share, epoch)
    }

    /// Loads the next shareholder from local storage for the given epoch.
    fn load_next_shareholder(&self, epoch: EpochTime) -> Result<()> {
        let share = self
            .storage
            .load_next_secret_share(self.churp_id, epoch)
            .or_else(|err| ignore_error(err, Error::InvalidSecretShare))?; // Ignore previous shares.

        self.verify_and_add_shareholder(share, epoch)
    }

    fn verify_and_add_shareholder(
        &self,
        share: Option<VerifiableSecretShare<S::Group>>,
        epoch: EpochTime,
    ) -> Result<()> {
        let share = match share {
            Some(share) => share,
            None => return Ok(()),
        };

        // Verify that the host hasn't changed.
        let me = encode_shareholder::<S>(&self.node_id.0, &self.shareholder_dst)?;
        if share.secret_share().coordinate_x() != &me {
            return Err(Error::InvalidHost.into());
        }

        // Create a new shareholder.
        let shareholder = Arc::new(Shareholder::from(share));

        // Store the shareholder.
        self.add_shareholder(shareholder, epoch);

        Ok(())
    }

    /// Returns the dealer for the given epoch.
    fn get_dealer(&self, epoch: EpochTime) -> Result<Arc<Dealer<S::Group>>> {
        let dealer_guard = self.dealer.lock().unwrap();

        let dealer_info = match dealer_guard.as_ref() {
            Some(dealer_info) => dealer_info,
            None => return Err(Error::DealerNotFound.into()),
        };
        if dealer_info.epoch != epoch {
            return Err(Error::DealerNotFound.into());
        }

        Ok(dealer_info.dealer.clone())
    }

    /// Adds a dealer for the given epoch. If a dealer is already set,
    /// it will be overwritten.
    fn add_dealer(&self, dealer: Arc<Dealer<S::Group>>, epoch: EpochTime) {
        let mut dealer_guard = self.dealer.lock().unwrap();
        *dealer_guard = Some(DealerInfo { epoch, dealer });
    }

    /// Creates a new dealer for the given epoch.
    ///
    /// If a dealer for the same or any other epoch already exists, it will
    /// be removed, its bivariate polynomial overwritten, and permanently
    /// lost.
    ///
    /// Note that since the host controls the local storage, he can restart
    /// the enclave to create multiple dealers for the same epoch and then
    /// replace the last backup with a bivariate polynomial from a dealer
    /// of his choice. Therefore, it is essential to verify the bivariate
    /// polynomial after loading or when deriving bivariate shares.
    fn create_dealer(
        &self,
        epoch: EpochTime,
        threshold: u8,
        dealing_phase: bool,
    ) -> Result<Arc<Dealer<S::Group>>> {
        // Create a new dealer.
        let dealer = Dealer::create(threshold, dealing_phase, &mut OsRng)?;
        let dealer = Arc::new(dealer);

        // Encrypt and store the polynomial in case of a restart.
        let polynomial = dealer.bivariate_polynomial();
        self.storage
            .store_bivariate_polynomial(polynomial, self.churp_id, epoch)?;

        // Store the dealer.
        self.add_dealer(dealer.clone(), epoch);

        Ok(dealer)
    }

    /// Loads the dealer for the given epoch from the local storage and verifies
    /// it against the provided checksum.
    fn load_dealer(&self, epoch: EpochTime, checksum: Option<Hash>) -> Result<()> {
        // Skip if handoffs are disabled.
        if epoch == HANDOFFS_DISABLED {
            return Ok(());
        }

        // Load untrusted polynomial.
        let polynomial = self
            .storage
            .load_bivariate_polynomial(self.churp_id, epoch)
            .or_else(|err| ignore_error(err, Error::InvalidBivariatePolynomial))?; // Ignore previous dealers.

        let polynomial = match polynomial {
            Some(polynomial) => polynomial,
            None => return Ok(()),
        };

        // Create untrusted dealer.
        let dealer = Arc::new(Dealer::from(polynomial));

        // Verify that the host hasn't created multiple dealers for the same
        // epoch and replaced the polynomial that was used to prepare
        // the application.
        if let Some(checksum) = checksum {
            let verification_matrix = dealer.verification_matrix();
            let computed_checksum = self.checksum_verification_matrix(verification_matrix, epoch);

            if checksum != computed_checksum {
                return Err(Error::InvalidBivariatePolynomial.into());
            }
        }

        // Store the dealer.
        self.add_dealer(dealer, epoch);

        Ok(())
    }

    /// Removes the dealer if it belongs to a handoff that occurred
    /// at or before the given epoch.
    fn remove_dealer(&self, max_epoch: EpochTime) {
        let mut dealer_guard = self.dealer.lock().unwrap();
        if let Some(dealer_info) = dealer_guard.as_ref() {
            if dealer_info.epoch <= max_epoch {
                *dealer_guard = None;
            }
        }
    }

    /// Returns the handoff for the given epoch.
    fn get_handoff(&self, epoch: EpochTime) -> Result<Arc<Handoff<S::Group>>> {
        let handoff_guard = self.handoff.lock().unwrap();

        let handoff_info = handoff_guard
            .as_ref()
            .filter(|hi| hi.epoch == epoch)
            .ok_or(Error::HandoffNotFound)?;

        Ok(handoff_info.handoff.clone())
    }

    /// Creates a handoff for the next handoff epoch. If a handoff already
    /// exists, the existing one is returned.
    fn get_or_create_handoff(&self, status: &Status) -> Result<Arc<Handoff<S::Group>>> {
        // Make sure to lock the handoff so that we don't create two handoffs
        // for the same epoch.
        let mut handoff_guard = self.handoff.lock().unwrap();

        if let Some(handoff_info) = handoff_guard.as_ref() {
            match status.next_handoff.cmp(&handoff_info.epoch) {
                cmp::Ordering::Less => return Err(Error::InvalidHandoff.into()),
                cmp::Ordering::Equal => return Ok(handoff_info.handoff.clone()),
                cmp::Ordering::Greater => (),
            }
        }

        // Create a new handoff.
        let threshold = status.threshold;
        let me = encode_shareholder::<S>(&self.node_id.0, &self.shareholder_dst)?;
        let mut shareholders = Vec::with_capacity(status.applications.len());
        for id in status.applications.keys() {
            let x = encode_shareholder::<S>(&id.0, &self.shareholder_dst)?;
            shareholders.push(x);
        }
        let kind = Self::handoff_kind(status);
        let handoff = Handoff::new(threshold, me, shareholders, kind)?;
        let handoff = Arc::new(handoff);

        // If the committee hasn't changed, we need the latest shareholder
        // to randomize its share.
        if kind == HandoffKind::CommitteeUnchanged {
            let shareholder = self.get_shareholder(status.handoff)?;
            handoff.set_shareholder(shareholder)?;
        }

        // Store the handoff.
        *handoff_guard = Some(HandoffInfo {
            epoch: status.next_handoff,
            handoff: handoff.clone(),
        });

        Ok(handoff)
    }

    // Removes the handoff if it happened at or before the given epoch.
    fn remove_handoff(&self, max_epoch: EpochTime) {
        let mut handoff_guard = self.handoff.lock().unwrap();
        if let Some(handoff_info) = handoff_guard.as_ref() {
            if handoff_info.epoch <= max_epoch {
                *handoff_guard = None;
            }
        }
    }

    /// Verifies parameters of the last successfully completed handoff against
    /// the latest status.
    fn verify_last_handoff(&self, epoch: EpochTime) -> Result<Status> {
        let status = self.churp_state.status(self.runtime_id, self.churp_id)?;
        if status.handoff != epoch {
            return Err(Error::HandoffMismatch.into());
        }

        Ok(status)
    }

    /// Verifies parameters of the next handoff against the latest status
    /// and checks whether the handoff is in progress.
    fn verify_next_handoff(&self, epoch: EpochTime) -> Result<Status> {
        let status = self.churp_state.status(self.runtime_id, self.churp_id)?;
        if status.next_handoff != epoch {
            return Err(Error::HandoffMismatch.into());
        }

        let now = self.beacon_state.epoch()?;
        if status.next_handoff != now {
            return Err(Error::HandoffClosed.into());
        }

        Ok(status)
    }

    /// Verifies the node ID by comparing the session's runtime attestation
    /// key (RAK) with the one published in the consensus layer.
    fn verify_node_id(&self, ctx: &RpcContext, node_id: &PublicKey) -> Result<()> {
        if !cfg!(any(target_env = "sgx", feature = "debug-mock-sgx")) {
            // Skip verification in non-SGX environments because those
            // nodes do not publish RAK in the consensus nor do they
            // send RAK binding when establishing Noise sessions.
            return Ok(());
        }

        let remote_rak = Self::remote_rak(ctx)?;
        let rak = self
            .registry_state
            .rak(node_id, &self.runtime_id)?
            .ok_or(Error::NotAuthenticated)?;

        if remote_rak != rak {
            return Err(Error::NotAuthorized.into());
        }

        Ok(())
    }

    /// Authorizes the remote key manager enclave so that secret data is never
    /// revealed to an unauthorized enclave.
    fn verify_km_enclave(&self, ctx: &RpcContext, policy: &SignedPolicySGX) -> Result<()> {
        if Self::ignore_policy() {
            return Ok(());
        }
        let remote_enclave = Self::remote_enclave(ctx)?;
        let policy = self.policies.verify(policy)?;
        if !policy.may_join(remote_enclave) {
            return Err(Error::NotAuthorized.into());
        }
        Ok(())
    }

    /// Authorizes the remote runtime enclave so that secret data is never
    /// revealed to an unauthorized enclave.
    fn verify_rt_enclave(
        &self,
        ctx: &RpcContext,
        policy: &SignedPolicySGX,
        runtime_id: &Namespace,
    ) -> Result<()> {
        if Self::ignore_policy() {
            return Ok(());
        }
        let remote_enclave = Self::remote_enclave(ctx)?;
        let policy = self.policies.verify(policy)?;
        if !policy.may_query(remote_enclave, runtime_id) {
            return Err(Error::NotAuthorized.into());
        }
        Ok(())
    }

    /// Returns the session RAK of the remote enclave.
    fn remote_rak(ctx: &RpcContext) -> Result<PublicKey> {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(Error::NotAuthenticated)?;
        Ok(si.rak_binding.rak_pub())
    }

    /// Returns the identity of the remote enclave.
    fn remote_enclave(ctx: &RpcContext) -> Result<&EnclaveIdentity> {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(Error::NotAuthenticated)?;
        Ok(&si.verified_attestation.quote.identity)
    }

    /// Returns true if key manager policies should be ignored.
    fn ignore_policy() -> bool {
        option_env!("OASIS_UNSAFE_SKIP_KM_POLICY").is_some()
    }

    /// Returns a key manager client that connects only to enclaves eligible
    /// to form a new committee or to enclaves belonging the old committee.
    fn key_manager_client(&self, status: &Status, new_committee: bool) -> Result<RemoteClient> {
        let enclaves = if Self::ignore_policy() {
            None
        } else {
            let policy = self.policies.verify(&status.policy)?;
            let enclaves = match new_committee {
                true => policy.may_join.clone(),
                false => policy.may_share.clone(),
            };
            Some(enclaves)
        };

        let client = RemoteClient::new_runtime_with_enclaves_and_policy(
            self.runtime_id,
            Some(self.runtime_id),
            enclaves,
            self.identity.quote_policy(),
            self.protocol.clone(),
            self.consensus_verifier.clone(),
            self.identity.clone(),
            1, // Not used, doesn't matter.
            vec![],
        );

        Ok(client)
    }

    /// Computes the checksum of the verification matrix.
    fn checksum_verification_matrix<G>(
        &self,
        matrix: &VerificationMatrix<G>,
        epoch: EpochTime,
    ) -> Hash
    where
        G: Group + GroupEncoding,
    {
        self.checksum_verification_matrix_bytes(&matrix.to_bytes(), epoch)
    }

    /// Computes the checksum of the verification matrix bytes.
    fn checksum_verification_matrix_bytes(&self, bytes: &Vec<u8>, epoch: EpochTime) -> Hash {
        let mut checksum = [0u8; 32];
        let mut f = KMac::new_kmac256(bytes, CHECKSUM_VERIFICATION_MATRIX_CUSTOM);
        f.update(&self.runtime_id.0);
        f.update(&[self.churp_id]);
        f.update(&epoch.to_le_bytes());
        f.finalize(&mut checksum);
        Hash(checksum)
    }

    /// Returns the type of the next handoff depending on which nodes submitted
    /// an application to form the next committee.
    fn handoff_kind(status: &Status) -> HandoffKind {
        if status.committee.is_empty() {
            return HandoffKind::DealingPhase;
        }
        if status.committee.len() != status.applications.len() {
            return HandoffKind::CommitteeChanged;
        }
        if status
            .committee
            .iter()
            .all(|value| status.applications.contains_key(value))
        {
            return HandoffKind::CommitteeUnchanged;
        }
        HandoffKind::CommitteeChanged
    }

    /// Extends the given domain separation tag with key manager runtime ID
    /// and churp ID.
    fn domain_separation_tag(context: &[u8], runtime_id: &Namespace, churp_id: u8) -> Vec<u8> {
        let mut dst = context.to_vec();
        dst.extend(RUNTIME_CONTEXT_SEPARATOR);
        dst.extend(runtime_id.0);
        dst.extend(CHURP_CONTEXT_SEPARATOR);
        dst.extend(&[churp_id]);
        dst
    }
}

impl<S: Suite> Handler for Instance<S> {
    fn verification_matrix(&self, req: &QueryRequest) -> Result<Vec<u8>> {
        let status = self.verify_last_handoff(req.epoch)?;
        let shareholder = match status.suite_id {
            SuiteId::NistP384Sha3_384 => self.get_shareholder(req.epoch)?,
        };
        let vm = shareholder
            .verifiable_share()
            .verification_matrix()
            .to_bytes();

        Ok(vm)
    }

    fn share_reduction_switch_point(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>> {
        let status = self.verify_next_handoff(req.epoch)?;

        let kind = Self::handoff_kind(&status);
        if !matches!(kind, HandoffKind::CommitteeChanged) {
            return Err(Error::InvalidHandoff.into());
        }

        let node_id = req.node_id.as_ref().ok_or(Error::NotAuthenticated)?;
        if !status.applications.contains_key(node_id) {
            return Err(Error::NotInCommittee.into());
        }

        self.verify_node_id(ctx, node_id)?;
        self.verify_km_enclave(ctx, &status.policy)?;

        let x = encode_shareholder::<S>(&node_id.0, &self.shareholder_dst)?;
        let shareholder = self.get_shareholder(status.handoff)?;
        let point = shareholder.switch_point(&x);
        let point = scalar_to_bytes(&point);

        Ok(point)
    }

    fn share_distribution_switch_point(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>> {
        let status = self.verify_next_handoff(req.epoch)?;

        let kind = Self::handoff_kind(&status);
        if !matches!(kind, HandoffKind::CommitteeChanged) {
            return Err(Error::InvalidHandoff.into());
        }

        let node_id = req.node_id.as_ref().ok_or(Error::NotAuthenticated)?;
        if !status.applications.contains_key(node_id) {
            return Err(Error::NotInCommittee.into());
        }

        self.verify_node_id(ctx, node_id)?;
        self.verify_km_enclave(ctx, &status.policy)?;

        let x = encode_shareholder::<S>(&node_id.0, &self.shareholder_dst)?;
        let handoff = self.get_handoff(status.next_handoff)?;
        let shareholder = handoff.get_reduced_shareholder()?;
        let point = shareholder.switch_point(&x);
        let point = scalar_to_bytes(&point);

        Ok(point)
    }

    fn bivariate_share(
        &self,
        ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<EncodedVerifiableSecretShare> {
        let status = self.verify_next_handoff(req.epoch)?;

        let node_id = req.node_id.as_ref().ok_or(Error::NotAuthenticated)?;
        if !status.applications.contains_key(node_id) {
            return Err(Error::NotInCommittee.into());
        };

        let application = status
            .applications
            .get(&self.node_id)
            .ok_or(Error::NotInCommittee)?;

        self.verify_node_id(ctx, node_id)?;
        self.verify_km_enclave(ctx, &status.policy)?;

        let x = encode_shareholder::<S>(&node_id.0, &self.shareholder_dst)?;
        let kind = Self::handoff_kind(&status);
        let dealer = self.get_dealer(status.next_handoff)?;
        let share = dealer.make_share(x, kind);
        let share = (&share).into();
        let verification_matrix = dealer.verification_matrix().to_bytes();

        // Verify that the host hasn't created multiple dealers for the same
        // epoch and replaced the polynomial that was used to prepare
        // the application.
        let computed_checksum =
            self.checksum_verification_matrix_bytes(&verification_matrix, status.next_handoff);
        if application.checksum != computed_checksum {
            return Err(Error::InvalidBivariatePolynomial.into());
        }

        Ok(EncodedVerifiableSecretShare {
            share,
            verification_matrix,
        })
    }

    fn sgx_policy_key_share(
        &self,
        ctx: &RpcContext,
        req: &KeyShareRequest,
    ) -> Result<EncodedEncryptedPoint> {
        let status = self.verify_last_handoff(req.epoch)?;

        self.verify_rt_enclave(ctx, &status.policy, &req.key_runtime_id)?;

        let shareholder = self.get_shareholder(status.handoff)?;
        let point = shareholder.make_key_share::<S>(&req.key_id.0, &self.sgx_policy_key_id_dst)?;
        Ok((&point).into())
    }

    fn apply(&self, req: &HandoffRequest) -> Result<SignedApplicationRequest> {
        let status = self.churp_state.status(self.runtime_id, self.churp_id)?;
        if status.next_handoff != req.epoch {
            return Err(Error::HandoffMismatch.into());
        }
        if status.next_handoff == HANDOFFS_DISABLED {
            return Err(Error::HandoffsDisabled.into());
        }
        if status.applications.contains_key(&self.node_id) {
            return Err(Error::ApplicationSubmitted.into());
        }

        // Ensure application is submitted one epoch before the next handoff.
        let now = self.beacon_state.epoch()?;
        if status.next_handoff != now + 1 {
            return Err(Error::ApplicationsClosed.into());
        }

        // Create a new dealer.
        let dealing_phase = status.committee.is_empty();
        let dealer = self.create_dealer(status.next_handoff, status.threshold, dealing_phase)?;

        // Fetch verification matrix and compute its checksum.
        let matrix = dealer.verification_matrix();
        let checksum = self.checksum_verification_matrix(matrix, req.epoch);

        // Prepare response and sign it with RAK.
        let application = ApplicationRequest {
            id: self.churp_id,
            runtime_id: self.runtime_id,
            epoch: status.next_handoff,
            checksum,
        };
        let body = cbor::to_vec(application.clone());
        let signature = self
            .signer
            .sign(APPLICATION_REQUEST_SIGNATURE_CONTEXT, &body)?;

        Ok(SignedApplicationRequest {
            application,
            signature,
        })
    }

    fn share_reduction(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let status = self.verify_next_handoff(req.epoch)?;

        let handoff = self.get_or_create_handoff(&status)?;
        let client = self.key_manager_client(&status, false)?;
        let f =
            |node_id| self.fetch_share_reduction_switch_point(node_id, &status, &handoff, &client);
        fetch(f, &req.node_ids)
    }

    fn share_distribution(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let status = self.verify_next_handoff(req.epoch)?;
        let handoff = self.get_handoff(status.next_handoff)?;
        let client = self.key_manager_client(&status, true)?;
        let f = |node_id| {
            self.fetch_share_distribution_switch_point(node_id, &status, &handoff, &client)
        };
        fetch(f, &req.node_ids)
    }

    fn proactivization(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let status = self.verify_next_handoff(req.epoch)?;
        let handoff = match Self::handoff_kind(&status) {
            HandoffKind::CommitteeChanged => self.get_handoff(status.next_handoff)?,
            _ => self.get_or_create_handoff(&status)?,
        };
        let client = self.key_manager_client(&status, true)?;
        let f = |node_id| self.fetch_bivariate_share(node_id, &status, &handoff, &client);
        fetch(f, &req.node_ids)
    }

    fn confirmation(&self, req: &HandoffRequest) -> Result<SignedConfirmationRequest> {
        let status = self.verify_next_handoff(req.epoch)?;

        if !status.applications.contains_key(&self.node_id) {
            return Err(Error::ApplicationNotSubmitted.into());
        }

        // Fetch the next shareholder and its secret share.
        let handoff = self.get_handoff(status.next_handoff)?;
        let shareholder = handoff.get_full_shareholder()?;
        let share = shareholder.verifiable_share();

        // Back up the secret share before sending confirmation.
        self.storage
            .store_next_secret_share(share, self.churp_id, status.next_handoff)?;

        // Store the shareholder. Observe that we are adding the shareholder
        // before the consensus has confirmed that the handoff was completed.
        // This is fine, as we always verify the handoff epoch before fetching
        // a shareholder.
        self.add_shareholder(shareholder.clone(), status.next_handoff);

        // Prepare response and sign it with RAK.
        let vm = share.verification_matrix();
        let checksum = self.checksum_verification_matrix(vm, status.next_handoff);
        let confirmation = ConfirmationRequest {
            id: self.churp_id,
            runtime_id: self.runtime_id,
            epoch: status.next_handoff,
            checksum,
        };
        let body = cbor::to_vec(confirmation.clone());
        let signature = self
            .signer
            .sign(CONFIRMATION_REQUEST_SIGNATURE_CONTEXT, &body)?;

        Ok(SignedConfirmationRequest {
            confirmation,
            signature,
        })
    }

    fn finalize(&self, req: &HandoffRequest) -> Result<()> {
        let status = self.verify_last_handoff(req.epoch)?;

        // Cleanup shareholders by removing those for past or failed handoffs.
        let epochs = [status.handoff, status.next_handoff];
        self.keep_shareholders(&epochs);

        // Cleaning up dealers and handoffs is optional,
        // as they are overwritten during the next handoff.
        let max_epoch = status.next_handoff.saturating_sub(1);
        self.remove_dealer(max_epoch);
        self.remove_handoff(max_epoch);

        // Fetch the last shareholder and its secret share.
        let shareholder = match self.get_shareholder(status.handoff) {
            Ok(shareholder) => shareholder,
            Err(_) => return Ok(()), // Not found.
        };
        let share = shareholder.verifiable_share();

        // Back up the secret share. This operation will be a no-op
        // if the handoff failed, as the last shareholder hasn't changed.
        self.storage
            .store_secret_share(share, self.churp_id, status.handoff)
    }
}

/// Replaces the given error with `Ok(None)`.
fn ignore_error<T>(err: anyhow::Error, ignore: Error) -> Result<Option<T>> {
    match err.downcast_ref::<Error>() {
        Some(error) if error == &ignore => Ok(None),
        _ => Err(err),
    }
}

/// Fetches data from the given nodes by calling the provided function
/// for each node.
fn fetch<F>(f: F, node_ids: &[PublicKey]) -> Result<FetchResponse>
where
    F: Fn(PublicKey) -> Result<bool>,
{
    let mut completed = false;
    let mut succeeded = vec![];
    let mut failed = vec![];

    for &node_id in node_ids {
        if completed {
            break;
        }

        match f(node_id) {
            Ok(done) => {
                completed = done;
                succeeded.push(node_id);
            }
            Err(_) => {
                failed.push(node_id);
            }
        }
    }

    Ok(FetchResponse {
        completed,
        succeeded,
        failed,
    })
}
