//! CHURP handler.
use std::{
    any::Any,
    cmp,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
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
    churp::{Dealer, DealerParams, NistP384, Player},
    vss::matrix::VerificationMatrix,
};

use crate::beacon::State as BeaconState;

use super::{
    storage::Storage, ApplicationRequest, Error, HandoffRequest, SignedApplicationRequest,
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

    /// Runtime attestation key signer.
    signer: Arc<dyn Signer>,
    /// Storage handler.
    storage: Storage,

    churp_state: ChurpState,
    beacon_state: BeaconState,

    /// Players with secret shares for the last successfully completed handoff,
    /// one per scheme.
    players: Mutex<HashMap<u8, HandoffData>>,
    /// Dealers of bivariate shares for the next handoff, one per scheme.
    dealers: Mutex<HashMap<u8, HandoffData>>,
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

        let players = Mutex::new(HashMap::new());
        let dealers = Mutex::new(HashMap::new());

        Self {
            signer,
            node_id,
            runtime_id,
            storage,
            churp_state,
            beacon_state,
            players,
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
    pub fn init(&self, req: &HandoffRequest) -> Result<SignedApplicationRequest> {
        // Verify request.
        let epoch = self.beacon_state.epoch()?;
        let status = self.churp_state.status(self.runtime_id, req.id)?;

        if req.runtime_id != self.runtime_id {
            return Err(Error::RuntimeMismatch.into());
        }
        if status.next_handoff != req.epoch {
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
        epoch: EpochTime,
        threshold: u8,
        dealing_phase: bool,
    ) -> Result<SignedApplicationRequest>
    where
        D: DealerParams + 'static,
    {
        let dealer = self.get_or_create_dealer::<D>(churp_id, epoch, threshold, dealing_phase)?;

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

    /// Returns the player for the specified scheme and handoff epoch.
    fn get_player<D>(&self, churp_id: u8, epoch: EpochTime) -> Result<Arc<Player<D>>>
    where
        D: DealerParams + 'static,
    {
        // Check the memory first. Make sure to lock the new players so that we
        // don't create two players for the same handoff.
        let mut players = self.players.lock().unwrap();

        if let Some(data) = players.get(&churp_id) {
            match epoch.cmp(&data.epoch) {
                cmp::Ordering::Less => return Err(Error::InvalidHandoff.into()),
                cmp::Ordering::Equal => {
                    // Downcasting should never fail because the consensus ensures that
                    // the group ID cannot change.
                    let player = data
                        .object
                        .clone()
                        .downcast::<Player<D>>()
                        .or(Err(Error::PlayerMismatch))?;

                    return Ok(player);
                }
                cmp::Ordering::Greater => (),
            }
        }

        // Fetch player's secret share from the local storage and use it to
        // restore the internal state upon restarts, unless a malicious
        // host has cleared the storage.
        let share = self
            .storage
            .load_secret_share::<D::Group>(churp_id, epoch)
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
        let share = share.ok_or(Error::PlayerNotFound)?;

        // Create a new player.
        let player = Arc::new(Player::from(share));
        let data = HandoffData {
            epoch,
            object: player.clone(),
        };
        players.insert(churp_id, data);

        Ok(player)
    }

    /// Adds a player for the specified scheme and handoff epoch.
    fn add_player<D>(&self, player: Arc<Player<D>>, churp_id: u8, epoch: EpochTime)
    where
        D: DealerParams + 'static,
    {
        let mut players = self.players.lock().unwrap();

        if let Some(data) = players.get(&churp_id) {
            if epoch <= data.epoch {
                return;
            }
        }

        let data = HandoffData {
            epoch,
            object: player,
        };
        players.insert(churp_id, data);
    }

    /// Removes player for the specified scheme if the player belongs
    /// to a handoff that happened at or before the given epoch.
    fn remove_player(&self, churp_id: u8, max_epoch: EpochTime) {
        let mut players = self.players.lock().unwrap();
        let data = match players.get(&churp_id) {
            Some(data) => data,
            None => return,
        };

        if data.epoch > max_epoch {
            return;
        }

        players.remove(&churp_id);
    }

    /// Returns the dealer for the specified scheme and handoff epoch.
    fn get_dealer<D>(&self, churp_id: u8, epoch: EpochTime) -> Result<Arc<Dealer<D>>>
    where
        D: DealerParams + 'static,
    {
        self._get_or_create_dealer(churp_id, epoch, None, None)
    }

    /// Returns the dealer for the specified scheme and handoff epoch.
    /// If the dealer doesn't exist, a new one is created.
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
        self._get_or_create_dealer(churp_id, epoch, Some(threshold), Some(dealing_phase))
    }

    fn _get_or_create_dealer<D>(
        &self,
        churp_id: u8,
        epoch: EpochTime,
        threshold: Option<u8>,
        dealing_phase: Option<bool>,
    ) -> Result<Arc<Dealer<D>>>
    where
        D: DealerParams + 'static,
    {
        // Check the memory first. Make sure to lock the dealers so that we
        // don't create two dealers for the same handoff.
        let mut dealers = self.dealers.lock().unwrap();

        if let Some(data) = dealers.get(&churp_id) {
            match epoch.cmp(&data.epoch) {
                cmp::Ordering::Less => return Err(Error::InvalidHandoff.into()),
                cmp::Ordering::Equal => {
                    // Downcasting should never fail because the consensus ensures that
                    // the group ID cannot change.
                    let dealer = data
                        .object
                        .clone()
                        .downcast::<Dealer<D>>()
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
            .load_bivariate_polynomial::<D::PrimeField>(churp_id, epoch)
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
                let dealer = Dealer::new(threshold, dealing_phase, &mut OsRng);

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
}

/// Replaces the given error with `Ok(None)`.
fn ignore_error<T>(err: anyhow::Error, ignore: Error) -> Result<Option<T>> {
    match err.downcast_ref::<Error>() {
        Some(error) if error == &ignore => Ok(None),
        _ => Err(err),
    }
}
