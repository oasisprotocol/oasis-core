//! CHURP handler.
use std::{
    any::Any,
    cmp,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use group::{Group, GroupEncoding};
use rand::rngs::OsRng;
use sp800_185::KMac;

#[cfg(target_env = "sgx")]
use oasis_core_runtime::{
    common::sgx::EnclaveIdentity, consensus::keymanager::churp::SignedPolicySGX,
};
use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signer},
        },
        namespace::Namespace,
    },
    consensus::{
        beacon::EpochTime,
        keymanager::churp::{Status, SuiteId},
        verifier::Verifier,
    },
    enclave_rpc::Context as RpcContext,
    future::block_on,
    identity::Identity,
    protocol::ProtocolUntrustedLocalStorage,
    Protocol,
};

use secret_sharing::{
    churp::{Dealer, Handoff, HandoffKind, Shareholder, ShareholderId},
    suites::{p384, Suite},
    vss::{
        matrix::VerificationMatrix,
        polynomial::Polynomial,
        scalar::{scalar_from_bytes, scalar_to_bytes},
    },
};

use crate::{
    beacon::State as BeaconState,
    client::{KeyManagerClient, RemoteClient},
    registry::State as RegistryState,
};

use super::{
    storage::Storage, ApplicationRequest, ConfirmationRequest, EncodedSecretShare, Error,
    FetchRequest, FetchResponse, HandoffRequest, QueryRequest, SignedApplicationRequest,
    SignedConfirmationRequest, State as ChurpState, VerifiedPolicies,
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

/// Data associated with a handoff.
struct HandoffData {
    /// The epoch of the handoff.
    epoch: EpochTime,

    /// Opaque object belonging to the handoff.
    object: Arc<dyn Any + Send + Sync>,
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
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    registry_state: RegistryState,

    /// Shareholders with secret shares for the last successfully completed
    /// handoff, one per scheme.
    shareholders: Mutex<HashMap<u8, HandoffData>>,
    /// Dealers of bivariate shares for the next handoff, one per scheme.
    dealers: Mutex<HashMap<u8, HandoffData>>,
    /// Next handoffs, limited to one per scheme.
    handoffs: Mutex<HashMap<u8, HandoffData>>,

    /// Cached verified policies.
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    policies: VerifiedPolicies,
}

impl Churp {
    pub fn new(
        node_id: PublicKey,
        identity: Arc<Identity>,
        protocol: Arc<Protocol>,
        consensus_verifier: Arc<dyn Verifier>,
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
        let dealers = Mutex::new(HashMap::new());
        let handoffs = Mutex::new(HashMap::new());

        let policies = VerifiedPolicies::new();

        Self {
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
            dealers,
            handoffs,
            policies,
        }
    }

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
    pub fn verification_matrix(&self, req: &QueryRequest) -> Result<Vec<u8>> {
        let status = self.verify_last_handoff(req.id, req.runtime_id, req.epoch)?;
        let shareholder = match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.get_shareholder::<<p384::Sha3_384 as Suite>::Group>(req.id, req.epoch)?
            }
        };
        let vm = shareholder.verification_matrix().to_bytes();

        Ok(vm)
    }

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
    pub fn share_reduction_switch_point(
        &self,
        _ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        let kind = Self::handoff_kind(&status);
        if !matches!(kind, HandoffKind::CommitteeChanged) {
            return Err(Error::InvalidHandoff.into());
        }

        let node_id = req.node_id.as_ref().ok_or(Error::NotAuthenticated)?;
        if !status.applications.contains_key(node_id) {
            return Err(Error::NotInCommittee.into());
        }
        #[cfg(target_env = "sgx")]
        {
            self.verify_node_id(_ctx, node_id)?;
            self.verify_enclave(_ctx, &status.policy)?;
        }

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.derive_share_reduction_switch_point::<p384::Sha3_384>(node_id, &status)
            }
        }
    }

    fn derive_share_reduction_switch_point<S>(
        &self,
        node_id: &PublicKey,
        status: &Status,
    ) -> Result<Vec<u8>>
    where
        S: Suite + 'static,
    {
        let id = ShareholderId(node_id.0).encode::<S>()?;
        let shareholder = self.get_shareholder::<S::Group>(status.id, status.handoff)?;
        let point = shareholder.switch_point(&id);
        let point = scalar_to_bytes(&point);

        Ok(point)
    }

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
    pub fn share_distribution_switch_point(
        &self,
        _ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<Vec<u8>> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        let kind = Self::handoff_kind(&status);
        if !matches!(kind, HandoffKind::CommitteeChanged) {
            return Err(Error::InvalidHandoff.into());
        }

        let node_id = req.node_id.as_ref().ok_or(Error::NotAuthenticated)?;
        if !status.applications.contains_key(node_id) {
            return Err(Error::NotInCommittee.into());
        }
        #[cfg(target_env = "sgx")]
        {
            self.verify_node_id(_ctx, node_id)?;
            self.verify_enclave(_ctx, &status.policy)?;
        }

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.derive_share_distribution_point::<p384::Sha3_384>(node_id, &status)
            }
        }
    }

    fn derive_share_distribution_point<S>(
        &self,
        node_id: &PublicKey,
        status: &Status,
    ) -> Result<Vec<u8>>
    where
        S: Suite + 'static,
    {
        let id = ShareholderId(node_id.0).encode::<S>()?;
        let handoff = self.get_handoff::<S>(status.id, status.next_handoff)?;
        let shareholder = handoff.get_reduced_shareholder()?;
        let point = shareholder.switch_point(&id);
        let point = scalar_to_bytes(&point);

        Ok(point)
    }

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
    pub fn bivariate_share(
        &self,
        _ctx: &RpcContext,
        req: &QueryRequest,
    ) -> Result<EncodedSecretShare> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        let node_id = req.node_id.as_ref().ok_or(Error::NotAuthenticated)?;
        if !status.applications.contains_key(node_id) {
            return Err(Error::NotInCommittee.into());
        }
        #[cfg(target_env = "sgx")]
        {
            self.verify_node_id(_ctx, node_id)?;
            self.verify_enclave(_ctx, &status.policy)?;
        }

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.derive_bivariate_share::<p384::Sha3_384>(node_id, &status)
            }
        }
    }

    fn derive_bivariate_share<S>(
        &self,
        node_id: &PublicKey,
        status: &Status,
    ) -> Result<EncodedSecretShare>
    where
        S: Suite + 'static,
    {
        let id = ShareholderId(node_id.0).encode::<S>()?;
        let kind = Self::handoff_kind(status);
        let dealer = self.get_dealer::<S::Group>(status.id, status.next_handoff)?;
        let polynomial = dealer.derive_bivariate_share(&id, kind).to_bytes();
        let verification_matrix = dealer.verification_matrix().to_bytes();

        Ok(EncodedSecretShare {
            polynomial,
            verification_matrix,
        })
    }

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
    pub fn init(&self, req: &HandoffRequest) -> Result<SignedApplicationRequest> {
        if self.runtime_id != req.runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }

        let status = self.churp_state.status(self.runtime_id, req.id)?;
        if status.next_handoff != req.epoch {
            return Err(Error::HandoffMismatch.into());
        }
        if status.next_handoff == HANDOFFS_DISABLED {
            return Err(Error::HandoffsDisabled.into());
        }
        if status.applications.contains_key(&self.node_id) {
            return Err(Error::ApplicationSubmitted.into());
        }

        let now = self.beacon_state.epoch()?;
        if status.next_handoff != now + 1 {
            return Err(Error::ApplicationsClosed.into());
        }

        let dealing_phase = status.committee.is_empty();

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.do_init::<p384::Sha3_384>(req.id, req.epoch, status.threshold, dealing_phase)
            }
        }
    }

    fn do_init<S>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        threshold: u8,
        dealing_phase: bool,
    ) -> Result<SignedApplicationRequest>
    where
        S: Suite + 'static,
    {
        let dealer =
            self.get_or_create_dealer::<S::Group>(churp_id, epoch, threshold, dealing_phase)?;

        // Fetch verification matrix and compute its checksum.
        let matrix = dealer.verification_matrix();
        let checksum = Self::checksum_verification_matrix(matrix, self.runtime_id, churp_id, epoch);

        // Prepare response and sign it with RAK.
        let application = ApplicationRequest {
            id: churp_id,
            runtime_id: self.runtime_id,
            epoch,
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
    pub fn share_reduction(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.fetch_share_reduction_switch_points::<p384::Sha3_384>(&req.node_ids, &status)
            }
        }
    }

    /// Tries to fetch switch points for share reduction from the given nodes.
    pub fn fetch_share_reduction_switch_points<S>(
        &self,
        node_ids: &Vec<PublicKey>,
        status: &Status,
    ) -> Result<FetchResponse>
    where
        S: Suite + 'static,
    {
        let handoff = self.get_or_create_handoff::<S>(status)?;
        let client = self.key_manager_client(status, false)?;
        let f = |node_id| {
            self.fetch_share_reduction_switch_point::<S>(node_id, status, &handoff, &client)
        };
        fetch(f, node_ids)
    }

    /// Tries to fetch switch point for share reduction from the given node.
    pub fn fetch_share_reduction_switch_point<S>(
        &self,
        node_id: PublicKey,
        status: &Status,
        handoff: &Handoff<S>,
        client: &RemoteClient,
    ) -> Result<bool>
    where
        S: Suite + 'static,
    {
        let id = ShareholderId(node_id.0);

        if !handoff.needs_share_reduction_switch_point(&id)? {
            return Err(Error::InvalidShareholder.into());
        }

        // Fetch from the host node.
        if node_id == self.node_id {
            let me = id.encode::<S>()?;
            let shareholder = self.get_shareholder::<S::Group>(status.id, status.handoff)?;
            let point = shareholder.switch_point(&me);

            if handoff.needs_verification_matrix()? {
                // Local verification matrix is trusted.
                let vm = shareholder.verification_matrix().clone();
                handoff.set_verification_matrix(vm)?;
            }

            return handoff.add_share_reduction_switch_point(id, point);
        }

        // Fetch from the remote node.
        client.set_nodes(vec![node_id]);

        if handoff.needs_verification_matrix()? {
            // The remote verification matrix needs to be verified.
            let vm = block_on(client.verification_matrix(status.id, status.handoff))?;
            let checksum = Self::checksum_verification_matrix_bytes(
                &vm,
                self.runtime_id,
                status.id,
                status.handoff,
            );
            let status_checksum = status.checksum.ok_or(Error::InvalidHandoff)?; // Should never happen.
            if checksum != status_checksum {
                return Err(Error::InvalidVerificationMatrixChecksum.into());
            }

            let vm = VerificationMatrix::from_bytes(&vm)
                .ok_or(Error::VerificationMatrixDecodingFailed)?;
            handoff.set_verification_matrix(vm)?;
        }

        let point =
            block_on(client.share_reduction_point(status.id, status.next_handoff, self.node_id))?;
        let point = scalar_from_bytes(&point).ok_or(Error::PointDecodingFailed)?;

        handoff.add_share_reduction_switch_point(id, point)
    }

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
    pub fn share_distribution(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => self
                .fetch_share_distribution_switch_points::<p384::Sha3_384>(&req.node_ids, &status),
        }
    }

    /// Tries to fetch switch points for share distribution from the given nodes.
    pub fn fetch_share_distribution_switch_points<S>(
        &self,
        node_ids: &Vec<PublicKey>,
        status: &Status,
    ) -> Result<FetchResponse>
    where
        S: Suite + 'static,
    {
        let handoff = self.get_handoff::<S>(status.id, status.next_handoff)?;
        let client = self.key_manager_client(status, true)?;
        let f = |node_id| {
            self.fetch_share_distribution_switch_point::<S>(node_id, status, &handoff, &client)
        };
        fetch(f, node_ids)
    }

    /// Tries to fetch switch point for share reduction from the given node.
    pub fn fetch_share_distribution_switch_point<S>(
        &self,
        node_id: PublicKey,
        status: &Status,
        handoff: &Handoff<S>,
        client: &RemoteClient,
    ) -> Result<bool>
    where
        S: Suite + 'static,
    {
        let id = ShareholderId(node_id.0);

        if !handoff.needs_full_share_distribution_switch_point(&id)? {
            return Err(Error::InvalidShareholder.into());
        }

        // Fetch from the host node.
        if node_id == self.node_id {
            let me = id.encode::<S>()?;
            let shareholder = handoff.get_reduced_shareholder()?;
            let point = shareholder.switch_point(&me);

            return handoff.add_full_share_distribution_switch_point(id, point);
        }

        // Fetch from the remote node.
        client.set_nodes(vec![node_id]);
        let point = block_on(client.share_distribution_point(
            status.id,
            status.next_handoff,
            self.node_id,
        ))?;
        let point = scalar_from_bytes(&point).ok_or(Error::PointDecodingFailed)?;

        handoff.add_full_share_distribution_switch_point(id, point)
    }

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
    pub fn proactivization(&self, req: &FetchRequest) -> Result<FetchResponse> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => {
                self.fetch_bivariate_shares::<p384::Sha3_384>(&req.node_ids, &status)
            }
        }
    }

    /// Tries to fetch proactive bivariate shares from the given nodes.
    pub fn fetch_bivariate_shares<S>(
        &self,
        node_ids: &Vec<PublicKey>,
        status: &Status,
    ) -> Result<FetchResponse>
    where
        S: Suite + 'static,
    {
        let handoff = self.get_or_create_handoff::<S>(status)?;
        let client = self.key_manager_client(status, true)?;
        let f = |node_id| self.fetch_bivariate_share::<S>(node_id, status, &handoff, &client);
        fetch(f, node_ids)
    }

    /// Tries to fetch proactive bivariate share from the given node.
    pub fn fetch_bivariate_share<S>(
        &self,
        node_id: PublicKey,
        status: &Status,
        handoff: &Handoff<S>,
        client: &RemoteClient,
    ) -> Result<bool>
    where
        S: Suite + 'static,
    {
        let id = ShareholderId(node_id.0);

        if !handoff.needs_bivariate_share(&id)? {
            return Err(Error::InvalidShareholder.into());
        }

        // Fetch from the host node.
        if node_id == self.node_id {
            let me = id.encode::<S>()?;
            let kind = Self::handoff_kind(status);
            let dealer = self.get_dealer::<S::Group>(status.id, status.next_handoff)?;
            let q = dealer.derive_bivariate_share(&me, kind);
            let vm = dealer.verification_matrix().clone();

            return handoff.add_bivariate_share(id, q, vm);
        }

        // Fetch from the remote node.
        client.set_nodes(vec![node_id]);
        let share = block_on(client.bivariate_share(status.id, status.next_handoff, self.node_id))?;

        // The remote verification matrix needs to be verified.
        let checksum = Self::checksum_verification_matrix_bytes(
            &share.verification_matrix,
            self.runtime_id,
            status.id,
            status.next_handoff,
        );
        let application = status
            .applications
            .get(&node_id)
            .ok_or(Error::InvalidShareholder)?; // Should never happen, as we verify if we require this share.

        if checksum != application.checksum {
            return Err(Error::InvalidVerificationMatrixChecksum.into());
        }

        let q = Polynomial::from_bytes(&share.polynomial).ok_or(Error::PolynomialDecodingFailed)?;
        let vm = VerificationMatrix::from_bytes(&share.verification_matrix)
            .ok_or(Error::VerificationMatrixDecodingFailed)?;

        handoff.add_bivariate_share(id, q, vm)
    }

    /// Returns a signed confirmation request containing the checksum
    /// of the merged verification matrix.
    pub fn confirmation(&self, req: &HandoffRequest) -> Result<SignedConfirmationRequest> {
        let status = self.verify_next_handoff(req.id, req.runtime_id, req.epoch)?;

        if !status.applications.contains_key(&self.node_id) {
            return Err(Error::ApplicationNotSubmitted.into());
        }

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => self.prepare_confirmation::<p384::Sha3_384>(&status),
        }
    }

    fn prepare_confirmation<S>(&self, status: &Status) -> Result<SignedConfirmationRequest>
    where
        S: Suite + 'static,
    {
        let handoff = self.get_handoff::<S>(status.id, status.next_handoff)?;
        let shareholder = handoff.get_full_shareholder()?;
        let share = shareholder.secret_share();

        // Before overwriting the next secret share, make sure it was copied
        // and used to construct the last shareholder.
        let _ = self
            .get_shareholder::<S::Group>(status.id, status.handoff)
            .map(Some)
            .or_else(|err| ignore_error(err, Error::ShareholderNotFound))?; // Ignore if we don't have the correct share.

        // Always persist the secret share before sending confirmation.
        self.storage
            .store_next_secret_share(share, status.id, status.next_handoff)?;

        // Prepare response and sign it with RAK.
        let vm = share.verification_matrix();
        let checksum =
            Self::checksum_verification_matrix(vm, self.runtime_id, status.id, status.next_handoff);
        let confirmation = ConfirmationRequest {
            id: status.id,
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

    /// Finalizes the specified scheme by cleaning up obsolete dealers,
    /// handoffs, and shareholders. If the handoff was just completed,
    /// the shareholder is made available, and its share is persisted
    /// to the local storage.
    pub fn finalize(&self, req: &HandoffRequest) -> Result<()> {
        let status = self.verify_last_handoff(req.id, req.runtime_id, req.epoch)?;

        match status.suite_id {
            SuiteId::NistP384Sha3_384 => self.do_finalize::<p384::Sha3_384>(&status),
        }
    }

    fn do_finalize<S>(&self, status: &Status) -> Result<()>
    where
        S: Suite + 'static,
    {
        // Move the shareholder if the handoff was completed.
        let handoff = self.get_handoff::<S>(status.id, status.handoff);
        let handoff = match handoff {
            Ok(handoff) => Some(handoff),
            Err(err) => match err.downcast_ref::<Error>() {
                Some(err) if err == &Error::HandoffNotFound => None,
                _ => return Err(err),
            },
        };
        if let Some(handoff) = handoff {
            let shareholder = handoff.get_full_shareholder()?;
            let share = shareholder.secret_share();
            self.storage
                .store_secret_share(share, status.id, status.handoff)?;
            self.add_shareholder(shareholder, status.id, status.handoff);
        }

        // Cleanup.
        let max_epoch = status.handoff.saturating_sub(1);
        self.remove_shareholder(status.id, max_epoch);

        let max_epoch = status.next_handoff.saturating_sub(1);
        self.remove_dealer(status.id, max_epoch);
        self.remove_handoff(status.id, max_epoch);

        Ok(())
    }

    /// Returns the shareholder for the specified scheme and handoff epoch.
    fn get_shareholder<G>(&self, churp_id: u8, epoch: EpochTime) -> Result<Arc<Shareholder<G>>>
    where
        G: Group + GroupEncoding,
    {
        // Check the memory first. Make sure to lock the new shareholders
        // so that we don't create two shareholders for the same handoff.
        let mut shareholders = self.shareholders.lock().unwrap();

        if let Some(data) = shareholders.get(&churp_id) {
            match epoch.cmp(&data.epoch) {
                cmp::Ordering::Less => return Err(Error::InvalidHandoff.into()),
                cmp::Ordering::Equal => {
                    // Downcasting should never fail because the consensus
                    // ensures that the suite ID cannot change.
                    let shareholder = data
                        .object
                        .clone()
                        .downcast::<Shareholder<G>>()
                        .or(Err(Error::ShareholderMismatch))?;

                    return Ok(shareholder);
                }
                cmp::Ordering::Greater => (),
            }
        }

        // Fetch shareholder's secret share from the local storage and use it
        // to restore the internal state upon restarts, unless a malicious
        // host has cleared the storage.
        let share = self
            .storage
            .load_secret_share(churp_id, epoch)
            .or_else(|err| ignore_error(err, Error::InvalidSecretShare))?; // Ignore previous shares.

        let share = match share {
            Some(share) => Some(share),
            None => {
                // If the secret share is not available, check if the next handoff
                // succeeded as it might have been confirmed while we were away.
                let share = self
                    .storage
                    .load_next_secret_share(churp_id, epoch)
                    .or_else(|err| ignore_error(err, Error::InvalidSecretShare))?; // Ignore previous shares.

                // If the share is valid, copy it.
                if let Some(share) = share.as_ref() {
                    self.storage.store_secret_share(share, churp_id, epoch)?;
                }

                share
            }
        };
        let share = share.ok_or(Error::ShareholderNotFound)?;

        // Create a new shareholder.
        let shareholder = Arc::new(Shareholder::from(share));
        let data = HandoffData {
            epoch,
            object: shareholder.clone(),
        };
        shareholders.insert(churp_id, data);

        Ok(shareholder)
    }

    /// Adds a shareholder for the specified scheme and handoff epoch.
    fn add_shareholder<G>(&self, shareholder: Arc<Shareholder<G>>, churp_id: u8, epoch: EpochTime)
    where
        G: Group + GroupEncoding,
    {
        let mut shareholders = self.shareholders.lock().unwrap();

        if let Some(data) = shareholders.get(&churp_id) {
            if epoch <= data.epoch {
                return;
            }
        }

        let data = HandoffData {
            epoch,
            object: shareholder,
        };
        shareholders.insert(churp_id, data);
    }

    /// Removes shareholder for the specified scheme if the shareholder belongs
    /// to a handoff that happened at or before the given epoch.
    fn remove_shareholder(&self, churp_id: u8, max_epoch: EpochTime) {
        let mut shareholders = self.shareholders.lock().unwrap();
        let data = match shareholders.get(&churp_id) {
            Some(data) => data,
            None => return,
        };

        if data.epoch > max_epoch {
            return;
        }

        shareholders.remove(&churp_id);
    }

    /// Returns the dealer for the specified scheme and handoff epoch.
    fn get_dealer<G>(&self, churp_id: u8, epoch: EpochTime) -> Result<Arc<Dealer<G>>>
    where
        G: Group + GroupEncoding,
    {
        self._get_or_create_dealer(churp_id, epoch, None, None)
    }

    /// Returns the dealer for the specified scheme and handoff epoch.
    /// If the dealer doesn't exist, a new one is created.
    fn get_or_create_dealer<G>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        threshold: u8,
        dealing_phase: bool,
    ) -> Result<Arc<Dealer<G>>>
    where
        G: Group + GroupEncoding,
    {
        self._get_or_create_dealer(churp_id, epoch, Some(threshold), Some(dealing_phase))
    }

    fn _get_or_create_dealer<G>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        threshold: Option<u8>,
        dealing_phase: Option<bool>,
    ) -> Result<Arc<Dealer<G>>>
    where
        G: Group + GroupEncoding,
    {
        // Check the memory first. Make sure to lock the dealers so that we
        // don't create two dealers for the same handoff.
        let mut dealers = self.dealers.lock().unwrap();

        if let Some(data) = dealers.get(&churp_id) {
            match epoch.cmp(&data.epoch) {
                cmp::Ordering::Less => return Err(Error::InvalidHandoff.into()),
                cmp::Ordering::Equal => {
                    // Downcasting should never fail because the consensus
                    // ensures that the suite ID cannot change.
                    let dealer = data
                        .object
                        .clone()
                        .downcast::<Dealer<G>>()
                        .or(Err(Error::DealerMismatch))?;

                    return Ok(dealer);
                }
                cmp::Ordering::Greater => (),
            }
        }

        // Check the local storage to ensure that only one secret bivariate
        // polynomial is generated per handoff upon restarts, unless a malicious
        // host has cleared the storage.
        let polynomial = self
            .storage
            .load_bivariate_polynomial(churp_id, epoch)
            .or_else(|err| ignore_error(err, Error::InvalidBivariatePolynomial))?; // Ignore previous dealers.

        let dealer = match polynomial {
            Some(bp) => {
                // Polynomial verification is redundant as encryption prevents
                // tampering, while consensus ensures that the group ID remains
                // unchanged and that polynomial dimensions remain consistent
                // for any given pair of churp ID and handoff.
                Dealer::from(bp)
            }
            None => {
                // Skip dealer creation if not needed.
                let threshold = threshold.ok_or(Error::DealerNotFound)?;
                let dealing_phase = dealing_phase.ok_or(Error::DealerNotFound)?;

                // The local storage is either empty or contains a polynomial
                // from another handoff. It's time to prepare a new one.
                //
                // If the host has cleared the storage, other participants
                // will detect the polynomial change because the checksum
                // of the verification matrix in the submitted application
                // will also change.
                let dealer = Dealer::new(threshold, dealing_phase, &mut OsRng)?;

                // Encrypt and store the polynomial in case of a restart.
                let polynomial = dealer.bivariate_polynomial();
                self.storage
                    .store_bivariate_polynomial(polynomial, churp_id, epoch)?;

                dealer
            }
        };

        // Create a new dealer.
        let dealer = Arc::new(dealer);
        let data = HandoffData {
            epoch,
            object: dealer.clone(),
        };
        dealers.insert(churp_id, data);

        Ok(dealer)
    }

    /// Removes the dealer for the specified scheme if the dealer belongs
    /// to a handoff that happened at or before the given epoch.
    fn remove_dealer(&self, churp_id: u8, max_epoch: EpochTime) {
        let mut dealers = self.dealers.lock().unwrap();
        let data = match dealers.get(&churp_id) {
            Some(data) => data,
            None => return,
        };

        if data.epoch > max_epoch {
            return;
        }

        dealers.remove(&churp_id);
    }

    /// Returns the handoff for the specified scheme and handoff epoch.
    fn get_handoff<S>(&self, churp_id: u8, epoch: EpochTime) -> Result<Arc<Handoff<S>>>
    where
        S: Suite + 'static,
    {
        self._get_or_create_handoff(churp_id, epoch, None)
    }

    /// Returns the handoff for the specified scheme and the next handoff epoch.
    /// If the handoff doesn't exist, a new one is created.
    fn get_or_create_handoff<S>(&self, status: &Status) -> Result<Arc<Handoff<S>>>
    where
        S: Suite + 'static,
    {
        self._get_or_create_handoff(status.id, status.next_handoff, Some(status))
    }

    fn _get_or_create_handoff<S>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        status: Option<&Status>,
    ) -> Result<Arc<Handoff<S>>>
    where
        S: Suite + 'static,
    {
        // Check the memory first. Make sure to lock the handoffs so that we
        // don't create two handoffs for the same epoch.
        let mut handoffs = self.handoffs.lock().unwrap();

        if let Some(data) = handoffs.get(&churp_id) {
            match epoch.cmp(&data.epoch) {
                cmp::Ordering::Less => return Err(Error::InvalidHandoff.into()),
                cmp::Ordering::Equal => {
                    // Downcasting should never fail because the consensus
                    // ensures that the suite ID cannot change.
                    let handoff = data
                        .object
                        .clone()
                        .downcast::<Handoff<S>>()
                        .or(Err(Error::HandoffDowncastFailed))?;

                    return Ok(handoff);
                }
                cmp::Ordering::Greater => (),
            }
        }

        // Skip handoff creation if not needed.
        let status = status.ok_or(Error::HandoffNotFound)?;

        // Create a new handoff.
        let threshold = status.threshold;
        let me = ShareholderId(self.node_id.0);
        let shareholders = status
            .applications
            .keys()
            .cloned()
            .map(|id| ShareholderId(id.0))
            .collect();
        let kind = Self::handoff_kind(status);
        let handoff = Handoff::new(threshold, me, shareholders, kind)?;

        if kind == HandoffKind::CommitteeUnchanged {
            let shareholder = self.get_shareholder(churp_id, status.handoff)?;
            handoff.set_shareholder(shareholder)?;
        }

        let handoff = Arc::new(handoff);
        let data = HandoffData {
            epoch,
            object: handoff.clone(),
        };
        handoffs.insert(churp_id, data);

        Ok(handoff)
    }

    /// Removes the dealer for the specified scheme if the dealer belongs
    /// to a handoff that happened at or before the given epoch.
    fn remove_handoff(&self, churp_id: u8, max_epoch: EpochTime) {
        let mut handoffs = self.handoffs.lock().unwrap();
        let data = match handoffs.get(&churp_id) {
            Some(data) => data,
            None => return,
        };

        if data.epoch > max_epoch {
            return;
        }

        handoffs.remove(&churp_id);
    }

    /// Verifies parameters of the last successfully completed handoff against
    /// the latest status.
    fn verify_last_handoff(
        &self,
        churp_id: u8,
        runtime_id: Namespace,
        epoch: EpochTime,
    ) -> Result<Status> {
        if self.runtime_id != runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }

        let status = self.churp_state.status(self.runtime_id, churp_id)?;
        if status.handoff != epoch {
            return Err(Error::HandoffMismatch.into());
        }

        Ok(status)
    }

    /// Verifies parameters of the next handoff against the latest status
    /// and checks whether the handoff is in progress.
    fn verify_next_handoff(
        &self,
        churp_id: u8,
        runtime_id: Namespace,
        epoch: EpochTime,
    ) -> Result<Status> {
        if self.runtime_id != runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }

        let status = self.churp_state.status(self.runtime_id, churp_id)?;
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
    #[cfg(target_env = "sgx")]
    fn verify_node_id(&self, ctx: &RpcContext, node_id: &PublicKey) -> Result<()> {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(Error::NotAuthenticated)?;
        let session_rak = si.rak_binding.rak_pub();

        let rak = self
            .registry_state
            .rak(node_id, &self.runtime_id)?
            .ok_or(Error::NotAuthenticated)?;

        if session_rak != rak {
            return Err(Error::NotAuthorized.into());
        }

        Ok(())
    }

    /// Authorizes the remote enclave so that secret data is never revealed
    /// to an unauthorized enclave.
    #[cfg(target_env = "sgx")]
    fn verify_enclave(&self, ctx: &RpcContext, policy: &SignedPolicySGX) -> Result<()> {
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

    /// Returns the identity of the remote enclave.
    #[cfg(target_env = "sgx")]
    fn remote_enclave(ctx: &RpcContext) -> Result<&EnclaveIdentity> {
        let si = ctx.session_info.as_ref();
        let si = si.ok_or(Error::NotAuthenticated)?;
        Ok(&si.verified_quote.identity)
    }

    /// Returns true if key manager policies should be ignored.
    #[cfg(target_env = "sgx")]
    fn ignore_policy() -> bool {
        option_env!("OASIS_UNSAFE_SKIP_KM_POLICY").is_some()
    }

    /// Returns a key manager client that connects only to enclaves eligible
    /// to form a new committee or to enclaves belonging the old committee.
    fn key_manager_client(&self, _status: &Status, _new_committee: bool) -> Result<RemoteClient> {
        #[cfg(not(target_env = "sgx"))]
        let enclaves = None;
        #[cfg(target_env = "sgx")]
        let enclaves = if Self::ignore_policy() {
            None
        } else {
            let policy = self.policies.verify(&_status.policy)?;
            let enclaves = match _new_committee {
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
        matrix: &VerificationMatrix<G>,
        runtime_id: Namespace,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Hash
    where
        G: Group + GroupEncoding,
    {
        Self::checksum_verification_matrix_bytes(&matrix.to_bytes(), runtime_id, churp_id, epoch)
    }

    /// Computes the checksum of the verification matrix bytes.
    fn checksum_verification_matrix_bytes(
        bytes: &Vec<u8>,
        runtime_id: Namespace,
        churp_id: u8,
        epoch: EpochTime,
    ) -> Hash {
        let mut checksum = [0u8; 32];
        let mut f = KMac::new_kmac256(bytes, CHECKSUM_VERIFICATION_MATRIX_CUSTOM);
        f.update(&runtime_id.0);
        f.update(&[churp_id]);
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
