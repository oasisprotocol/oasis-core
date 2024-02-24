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
    self,
    common::{
        crypto::signature::{PublicKey, Signer},
        namespace::Namespace,
    },
    consensus::{
        beacon::EpochTime, state::keymanager::churp::GroupID,
        verifier::Verifier as ConsensusVerifier,
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

/// Context used for the application request signature.
const APPLICATION_REQUEST_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/keymanager/churp: application request";

const CHECKSUM_VERIFICATION_MATRIX_CUSTOM: &[u8] =
    b"oasis-core/keymanager/churp: verification matrix";

/// The maximum number of CHURP dealers kept in the cache.
const DEALERS_CACHE_SIZE: usize = 10;

/// Key manager application that implements churn-robust proactive secret
/// sharing scheme (CHURP).
pub struct Churp {
    runtime_id: Namespace,
    node_id: PublicKey,

    // Runtime attestation key signer.
    signer: Arc<dyn Signer>,
    // Storage handler.
    storage: Storage,

    churp_verifier: ChurpState,
    beacon_verifier: BeaconState,

    dealers: RwLock<LruCache<(Namespace, u64), Arc<dyn Any + Send + Sync>>>,
}

impl Churp {
    pub fn new(
        runtime_id: Namespace,
        identity: Arc<EnclaveIdentity>,
        consensus_verifier: Arc<dyn ConsensusVerifier>,
        storage: Arc<dyn KeyValue>,
    ) -> Self {
        let storage = Storage::new(storage);
        let signer: Arc<dyn Signer> = identity.clone();
        let churp_verifier = ChurpState::new(consensus_verifier.clone());
        let beacon_verifier = BeaconState::new(consensus_verifier.clone());

        let dealers = RwLock::new(LruCache::new(
            NonZeroUsize::new(DEALERS_CACHE_SIZE).unwrap(),
        ));

        Self {
            signer,
            runtime_id,
            node_id: Default::default(),
            storage,
            churp_verifier,
            beacon_verifier,
            dealers,
        }
    }

    /// Prepare CHURP for participation in the given round of the protocol.
    ///
    /// Initialization randomly selects a bivariate polynomial for the given
    /// round, computes the corresponding verification matrix and its checksum,
    /// and signs the latter.
    ///
    /// Bivariate polynomial:
    ///     B(x,y) = \sum_{i=0}^{t_n} \sum_{j=0}^{t_m} b_{i,j} x^i y^j
    ///
    /// Verification matrix:
    ///     M = [b_{i,j} * G]
    ///
    /// Checksum:
    ///     H = KMAC256(M, runtime ID, round)
    ///
    /// The bivariate polynomial is zero-hole in all rounds expect in the zero
    /// round (dealing phase).
    ///
    /// This method must be called locally.
    pub fn init(&self, req: &InitRequest) -> Result<SignedApplicationRequest> {
        // Verify request.
        let epoch = self.beacon_verifier.epoch()?;
        let status = self.churp_verifier.status(self.runtime_id, req.id)?;

        if req.runtime_id != self.runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }
        if status.round != req.round {
            return Err(Error::RoundMismatch.into());
        }
        if status.threshold == 0 {
            return Err(Error::ZeroThreshold.into());
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

        // For now, support only one group.
        match status.group_id {
            GroupID::NistP384 => self.do_init::<NistP384>(req.id, req.round, status.threshold),
        }
    }

    fn do_init<D>(
        &self,
        churp_id: u8,
        round: u64,
        threshold: u8,
    ) -> Result<SignedApplicationRequest>
    where
        D: DealerParams + 'static,
    {
        let dealer = self.get_or_create_dealer::<D>(churp_id, round, threshold)?;

        // Fetch verification matrix and compute its checksum.
        let matrix = dealer.verification_matrix();
        let checksum = Self::checksum_verification_matrix(matrix, self.runtime_id, round);

        // Prepare response and sign it with RAK.
        let application = ApplicationRequest {
            id: churp_id,
            runtime_id: self.runtime_id,
            round,
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
        round: u64,
        threshold: u8,
    ) -> Result<Arc<Dealer<D>>>
    where
        D: DealerParams + 'static,
    {
        // Check the memory first.
        let key = (self.runtime_id, round);
        let mut dealers = self.dealers.write().unwrap();

        if let Some(dealer) = dealers.get(&key) {
            // Downcasting should never fail because the consensus ensures that
            // the group ID cannot change.
            let dealer = dealer
                .downcast_ref::<Arc<Dealer<D>>>()
                .ok_or(Error::DealerMismatch)?;
            return Ok(dealer.clone());
        }

        // Check the local storage to ensure that only one secret bivariate
        // polynomial is generated per round upon restarts, unless a malicious
        // host has cleared the storage.
        let polynomial = self
            .storage
            .load_bivariate_polynomial::<D::PrimeField>(churp_id, round)?;

        let dealer = match polynomial {
            Some(bp) => {
                // Polynomial verification is redundant as encryption prevents
                // tampering, while consensus ensures that the group ID remains
                // unchanged and that polynomial dimensions remain consistent
                // for any given pair of churp ID and round.
                Dealer::new(bp)
            }
            None => {
                // The local storage is empty. It's time to prepare a new polynomial.
                // If the host has cleared the storage, other participants will detect
                // the polynomial change because the checksum of the verification matrix
                // in the submitted application will also change.
                let dx = threshold.saturating_sub(1);
                let dy = 2 * dx;

                let dealer = match round {
                    0 => Dealer::random(dx, dy, &mut OsRng),
                    _ => Dealer::zero_hole(dx, dy, &mut OsRng),
                };

                // Encrypt and store the polynomial in case of a restart.
                let polynomial = dealer.bivariate_polynomial();
                self.storage
                    .store_bivariate_polynomial(polynomial, churp_id, round)?;

                dealer

                // TODO: Delete previous polynomials. How? Should we call
                //       the host to clean storage?
            }
        };

        // Keep the most recent dealers in the memory.
        let dealer = Arc::new(dealer);
        dealers.put(key, dealer.clone());

        Ok(dealer)
    }

    fn checksum_verification_matrix<G>(
        matrix: &VerificationMatrix<G>,
        runtime_id: Namespace,
        round: u64,
    ) -> Vec<u8>
    where
        G: Group + GroupEncoding,
    {
        let mut checksum = [0u8; 32];
        let mut f = KMac::new_kmac256(&matrix.to_bytes(), CHECKSUM_VERIFICATION_MATRIX_CUSTOM);
        f.update(&runtime_id.0);
        f.update(&round.to_le_bytes());
        f.finalize(&mut checksum);
        checksum.to_vec()
    }
}
