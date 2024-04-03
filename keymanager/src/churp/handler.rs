//! CHURP handler.
use std::{
    any::Any,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use lru::LruCache;
use p256::elliptic_curve::{group::GroupEncoding, Group};
use rand::rngs::OsRng;
use sp800_185::KMac;

use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            signature::{PublicKey, Signer},
        },
        namespace::Namespace,
    },
    consensus::{
        beacon::EpochTime, keymanager::churp::GroupID, verifier::Verifier as ConsensusVerifier,
    },
    identity::Identity as EnclaveIdentity,
    storage::KeyValue,
};

use secret_sharing::{
    churp::{Dealer, DealerParams, NistP384},
    vss::matrix::VerificationMatrix,
};

use crate::beacon::State as BeaconState;

use super::{
    storage::Storage, ApplicationRequest, Error, InitRequest, SignedApplicationRequest,
    State as ChurpState,
};

/// A handoff interval that disables handoffs.
pub const HANDOFFS_DISABLED: EpochTime = 0xffffffffffffffff;

/// Signatures context for signing application requests.
const APPLICATION_REQUEST_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: application request";

/// Custom KMAC domain separation for checksums of verification matrices.
const CHECKSUM_VERIFICATION_MATRIX_CUSTOM: &[u8] =
    b"oasis-core/keymanager/churp: verification matrix";

/// The maximum number of CHURP dealers kept in the cache.
const DEALERS_CACHE_SIZE: usize = 10;

/// Key manager application that implements churn-robust proactive secret
/// sharing scheme (CHURP).
pub struct Churp {
    /// Host node identifier.
    node_id: PublicKey,
    /// Key manager runtime ID.
    runtime_id: Namespace,

    /// Runtime attestation key signer.
    signer: Arc<dyn Signer>,
    /// Storage handler.
    storage: Storage,

    churp_state: ChurpState,
    beacon_state: BeaconState,

    dealers: RwLock<LruCache<(u8, u64), Arc<dyn Any + Send + Sync>>>,
}

impl Churp {
    pub fn new(
        node_id: PublicKey,
        runtime_id: Namespace,
        identity: Arc<EnclaveIdentity>,
        consensus_verifier: Arc<dyn ConsensusVerifier>,
        storage: Arc<dyn KeyValue>,
    ) -> Self {
        let storage = Storage::new(storage);
        let signer: Arc<dyn Signer> = identity.clone();
        let churp_state = ChurpState::new(consensus_verifier.clone());
        let beacon_state = BeaconState::new(consensus_verifier.clone());

        let dealers = RwLock::new(LruCache::new(
            NonZeroUsize::new(DEALERS_CACHE_SIZE).unwrap(),
        ));

        Self {
            signer,
            node_id,
            runtime_id,
            storage,
            churp_state,
            beacon_state,
            dealers,
        }
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
    pub fn init(&self, req: &InitRequest) -> Result<SignedApplicationRequest> {
        // Verify request.
        let epoch = self.beacon_state.epoch()?;
        let status = self.churp_state.status(self.runtime_id, req.id)?;

        if req.runtime_id != self.runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }
        if status.next_handoff != req.handoff {
            return Err(Error::HandoffMismatch.into());
        }
        if status.next_handoff == HANDOFFS_DISABLED {
            return Err(Error::HandoffsDisabled.into());
        }
        if status.next_handoff != epoch + 1 {
            return Err(Error::ApplicationsClosed.into());
        }
        if status.applications.contains_key(&self.node_id) {
            return Err(Error::ApplicationsSubmitted.into());
        }

        let dealing_phase = status.committee.is_empty();

        // For now, support only one group.
        match status.group_id {
            GroupID::NistP384 => self.do_init::<NistP384>(
                req.id,
                status.next_handoff,
                status.threshold,
                dealing_phase,
            ),
        }
    }

    fn do_init<D>(
        &self,
        churp_id: u8,
        handoff: EpochTime,
        threshold: u8,
        dealing_phase: bool,
    ) -> Result<SignedApplicationRequest>
    where
        D: DealerParams + 'static,
    {
        let dealer = self.get_or_create_dealer::<D>(churp_id, handoff, threshold, dealing_phase)?;

        // Fetch verification matrix and compute its checksum.
        let matrix = dealer.verification_matrix();
        let checksum =
            Self::checksum_verification_matrix(matrix, self.runtime_id, churp_id, handoff);

        // Prepare response and sign it with RAK.
        let application = ApplicationRequest {
            id: churp_id,
            runtime_id: self.runtime_id,
            handoff,
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

    fn get_or_create_dealer<D>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        threshold: u8,
        dealing_phase: bool,
    ) -> Result<Arc<Dealer<D>>>
    where
        D: DealerParams + 'static,
    {
        // Check the memory first.
        let key = (churp_id, epoch);
        let mut dealers = self.dealers.write().unwrap();

        if let Some(dealer) = dealers.get(&key) {
            // Downcasting should never fail because the consensus ensures that
            // the group ID cannot change.
            let dealer = dealer
                .clone()
                .downcast::<Dealer<D>>()
                .or(Err(Error::DealerMismatch))?;

            return Ok(dealer);
        }

        // Check the local storage to ensure that only one secret bivariate
        // polynomial is generated per handoff upon restarts, unless a malicious
        // host has cleared the storage.
        let polynomial = self
            .storage
            .load_bivariate_polynomial::<D::PrimeField>(churp_id, epoch);
        let polynomial = match polynomial {
            Ok(polynomial) => Ok(polynomial),
            Err(err) => match err.downcast_ref::<Error>() {
                Some(Error::InvalidBivariatePolynomial) => Ok(None), // Ignore previous handoffs.
                _ => Err(err),
            },
        }?;

        let dealer = match polynomial {
            Some(bp) => {
                // Polynomial verification is redundant as encryption prevents
                // tampering, while consensus ensures that the group ID remains
                // unchanged and that polynomial dimensions remain consistent
                // for any given pair of churp ID and handoff.
                Dealer::from(bp)
            }
            None => {
                // The local storage is either empty or contains a polynomial
                // from another handoff. It's time to prepare a new one.
                //
                // If the host has cleared the storage, other participants
                // will detect the polynomial change because the checksum
                // of the verification matrix in the submitted application
                // will also change.
                let dealer = Dealer::new(threshold, dealing_phase, &mut OsRng);

                // Encrypt and store the polynomial in case of a restart.
                let polynomial = dealer.bivariate_polynomial();
                self.storage
                    .store_bivariate_polynomial(polynomial, churp_id, epoch)?;

                dealer
            }
        };

        // Keep the most recent dealers in memory.
        let dealer = Arc::new(dealer);
        dealers.put(key, dealer.clone());

        Ok(dealer)
    }

    fn checksum_verification_matrix<G>(
        matrix: &VerificationMatrix<G>,
        runtime_id: Namespace,
        churp_id: u8,
        handoff: EpochTime,
    ) -> Hash
    where
        G: Group + GroupEncoding,
    {
        let mut checksum = [0u8; 32];
        let mut f = KMac::new_kmac256(&matrix.to_bytes(), CHECKSUM_VERIFICATION_MATRIX_CUSTOM);
        f.update(&runtime_id.0);
        f.update(&[churp_id]);
        f.update(&handoff.to_le_bytes());
        f.finalize(&mut checksum);
        Hash(checksum)
    }
}
