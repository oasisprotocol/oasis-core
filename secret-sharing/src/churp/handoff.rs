use std::sync::Arc;

use anyhow::Result;
use group::{Group, GroupEncoding};

use crate::vss::VerificationMatrix;

use super::{DimensionSwitch, Error, Shareholder, VerifiableSecretShare};

/// Handoff kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffKind {
    /// The dealing phase is the initial setup phase where all (or some)
    /// participants act as dealers, sending polynomials (bivariate/dealer
    /// shares) and the verification matrix to all other participants.
    /// These polynomials and the matrix are derived from privately
    /// chosen non-zero-hole bivariate polynomial.
    ///
    /// The number of dealers during the dealing phase must be at least
    /// threshold + 2. This ensures that even if the threshold number
    /// of potentially Byzantine dealers reveal their privately chosen
    /// bivariate polynomial, the combined bivariate polynomial `B(x,y)`
    /// cannot be known by any single party. It's important to note that
    /// if only threshold + 1 shares have been combined, then the secret
    /// could be known by one honest shareholder.
    ///
    /// In this phase, dimension switching is not needed, so the handoff
    /// can be simplified. The share reduction phase is skipped entirely,
    /// and only the proactivization part of the full share distribution
    /// phase needs to be completed.
    DealingPhase,
    /// Handoffs, in which the committee doesn't change, are similar to
    /// the dealing phase. Here also, all (or some) participants act
    /// as dealers, sending polynomials (bivariate/dealer shares) and
    /// the verification matrix to all other participants. The difference,
    /// however, is that these polynomials and the matrix are derived from
    /// privately chosen zero-hole bivariate polynomial, ensuring that
    /// the shared secret is not changed when the distributed key shares
    /// are updated.
    ///
    /// In this phase, dimension switching is not needed, so the handoff
    /// can be simplified. The share reduction phase is skipped entirely,
    /// and only the proactivization part of the full share distribution
    /// phase needs to be completed.
    CommitteeUnchanged,
    /// Handoffs, during which the committee changes, use the dimension
    /// switching technique to transfer the secret from the old committee
    /// to a new one. Here also, all (or some) participants act as dealers,
    /// sending polynomials (bivariate/dealer shares) and the verification
    /// matrix to all other participants. These polynomials and the matrix
    /// must be derived from privately chosen zero-hole bivariate polynomial.
    ///
    /// The full handoff consists of two phases: share reduction and
    /// full share distribution. In the first phase, the new committee
    /// temporarily switches to a (2t, n)-threshold scheme by retrieving
    /// share reduction points from the old committee. These points are used
    /// to construct reduced shares which are then proactively updated
    /// to obtain proactive reduced shares. Once all participants construct
    /// those, the second phase begins in which the new committee switches
    /// back to a (t, n)-threshold scheme by exchanging full share distribution
    /// points and constructing full shares.
    CommitteeChanged,
}

impl HandoffKind {
    /// Indicates whether bivariate shares should be derived from a zero-hole
    /// bivariate polynomial.
    ///
    /// Should return false only in the dealing phase, where the sum of the
    /// bivariate shares defines the shared secret. In other handoffs, this
    /// should be true so that the shared secret remains unchanged.
    pub fn require_zero_hole(&self) -> bool {
        match &self {
            HandoffKind::DealingPhase => false,
            HandoffKind::CommitteeUnchanged => true,
            HandoffKind::CommitteeChanged => true,
        }
    }
}

/// Handoff proactivizes the shared secret (changes associated shares) while
/// transferring the secret from an old committee to a new, possibly
/// intersecting one.
pub struct Handoff<G: Group + GroupEncoding> {
    /// Handoff kind.
    kind: HandoffKind,

    /// The share reduction phase of the handoff.
    share_reduction: Option<DimensionSwitch<G>>,

    /// The share distribution phase of the handoff.
    share_distribution: Option<DimensionSwitch<G>>,
}

impl<G> Handoff<G>
where
    G: Group + GroupEncoding,
{
    /// Creates a new handoff using the given shareholders (new committee)
    /// to proactivize the shared secret.
    pub fn new(
        threshold: u8,
        me: G::Scalar,
        shareholders: Vec<G::Scalar>,
        kind: HandoffKind,
    ) -> Result<Self> {
        let (share_reduction, share_distribution) = match kind {
            HandoffKind::DealingPhase => {
                let share_distribution = DimensionSwitch::new_full_share_distribution(
                    threshold,
                    me,
                    shareholders,
                    kind,
                )?;
                share_distribution.skip_accumulating()?;
                share_distribution.start_merging(None)?;

                (None, Some(share_distribution))
            }
            HandoffKind::CommitteeUnchanged => {
                let share_distribution = DimensionSwitch::new_full_share_distribution(
                    threshold,
                    me,
                    shareholders,
                    kind,
                )?;
                share_distribution.skip_accumulating()?;

                (None, Some(share_distribution))
            }
            HandoffKind::CommitteeChanged => {
                let share_reduction =
                    DimensionSwitch::new_share_reduction(threshold, me, shareholders, kind)?;

                let share_distribution = DimensionSwitch::new_full_share_distribution(
                    threshold,
                    me,
                    Vec::new(), // Skip proactivization.
                    kind,
                )?;

                (Some(share_reduction), Some(share_distribution))
            }
        };

        Ok(Self {
            kind,
            share_reduction,
            share_distribution,
        })
    }

    /// Checks if the handoff needs the verification matrix from the previous
    /// handoff.
    pub fn needs_verification_matrix(&self) -> Result<bool> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        let needs = self
            .share_reduction
            .as_ref()
            .ok_or(Error::InvalidState)?
            .is_waiting_for_verification_matrix();

        Ok(needs)
    }

    /// Sets the verification matrix from the previous handoff.
    pub fn set_verification_matrix(&self, vm: VerificationMatrix<G>) -> Result<()> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_reduction
            .as_ref()
            .ok_or(Error::InvalidState)?
            .start_accumulating(vm)
    }

    /// Checks if the handoff needs the shareholder from the previous handoff.
    pub fn needs_shareholder(&self) -> Result<bool> {
        if self.kind != HandoffKind::CommitteeUnchanged {
            return Err(Error::InvalidKind.into());
        }

        let needs = self
            .share_distribution
            .as_ref()
            .ok_or(Error::InvalidState)?
            .is_waiting_for_shareholder();

        Ok(needs)
    }

    /// Sets the shareholder from the previous handoff.
    pub fn set_shareholder(&self, shareholder: Arc<Shareholder<G>>) -> Result<()> {
        if self.kind != HandoffKind::CommitteeUnchanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_distribution
            .as_ref()
            .ok_or(Error::InvalidState)?
            .start_merging(Some(shareholder))
    }

    /// Checks if share reduction needs a switch point from the given
    /// shareholder.
    pub fn needs_share_reduction_switch_point(&self, x: &G::Scalar) -> Result<bool> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_reduction
            .as_ref()
            .ok_or(Error::InvalidState)?
            .needs_switch_point(x)
    }

    /// Adds the given switch point to share reduction.
    pub fn add_share_reduction_switch_point(&self, x: G::Scalar, bij: G::Scalar) -> Result<bool> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_reduction
            .as_ref()
            .ok_or(Error::InvalidState)?
            .add_switch_point(x, bij)
    }

    /// Checks if full share distribution needs a switch point from the given
    /// shareholder.
    pub fn needs_full_share_distribution_switch_point(&self, x: &G::Scalar) -> Result<bool> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_distribution
            .as_ref()
            .ok_or(Error::InvalidState)?
            .needs_switch_point(x)
    }

    /// Adds the given switch point to full share distribution.
    pub fn add_full_share_distribution_switch_point(
        &self,
        x: G::Scalar,
        bij: G::Scalar,
    ) -> Result<bool> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_distribution
            .as_ref()
            .ok_or(Error::InvalidState)?
            .add_switch_point(x, bij)
    }

    /// Checks if bivariate share is needed from the given shareholder.
    pub fn needs_bivariate_share(&self, x: &G::Scalar) -> Result<bool> {
        let ds = match self.kind {
            HandoffKind::DealingPhase => &self.share_distribution,
            HandoffKind::CommitteeUnchanged => &self.share_distribution,
            HandoffKind::CommitteeChanged => &self.share_reduction,
        };

        ds.as_ref()
            .ok_or(Error::InvalidState)?
            .needs_bivariate_share(x)
    }

    /// Adds the given bivariate share.
    pub fn add_bivariate_share(
        &self,
        x: &G::Scalar,
        verifiable_share: VerifiableSecretShare<G>,
    ) -> Result<bool> {
        let ds = match self.kind {
            HandoffKind::DealingPhase => &self.share_distribution,
            HandoffKind::CommitteeUnchanged => &self.share_distribution,
            HandoffKind::CommitteeChanged => &self.share_reduction,
        };

        let res = ds
            .as_ref()
            .ok_or(Error::InvalidState)?
            .add_bivariate_share(x, verifiable_share);

        // Start full share distribution if share reduction has completed.
        if self.kind == HandoffKind::CommitteeChanged && res.as_ref().is_ok_and(|&done| done) {
            let vm = self
                .share_reduction
                .as_ref()
                .ok_or(Error::InvalidState)?
                .get_shareholder()?
                .verifiable_share()
                .verification_matrix()
                .clone();

            self.share_distribution
                .as_ref()
                .ok_or(Error::InvalidState)?
                .start_accumulating(vm)?;
        }

        res
    }

    /// Returns the shareholder resulting from share reduction.
    pub fn get_reduced_shareholder(&self) -> Result<Arc<Shareholder<G>>> {
        if self.kind != HandoffKind::CommitteeChanged {
            return Err(Error::InvalidKind.into());
        }

        self.share_reduction
            .as_ref()
            .ok_or(Error::InvalidState)?
            .get_shareholder()
    }

    /// Returns the shareholder resulting from full share distribution.
    pub fn get_full_shareholder(&self) -> Result<Arc<Shareholder<G>>> {
        self.share_distribution
            .as_ref()
            .ok_or(Error::InvalidState)?
            .get_shareholder()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::zip, sync::Arc};

    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use crate::{
        churp::{self, HandoffKind, VerifiableSecretShare},
        suites::{self, p384},
    };

    type Suite = p384::Sha3_384;
    type Group = <Suite as suites::Suite>::Group;
    type PrimeField = <Suite as suites::Suite>::PrimeField;
    type Shareholder = churp::Shareholder<Group>;
    type Dealer = churp::Dealer<Group>;
    type Handoff = churp::Handoff<Group>;

    fn prepare_shareholders(ids: &[u64]) -> Vec<PrimeField> {
        ids.into_iter().map(|&id| id.into()).collect()
    }

    fn verify_shareholders(shareholders: &[Arc<Shareholder>], threshold: u8, full_share: bool) {
        let mut vms = HashSet::new();
        for shareholder in shareholders {
            let share = shareholder.verifiable_share();

            // Verify that the share is valid.
            share
                .verify(threshold, false, full_share)
                .expect("share should be valid");

            // Verify that all shareholders have the same matrix.
            let bytes = share.verification_matrix().to_bytes();
            vms.insert(bytes);

            if vms.len() != 1 {
                panic!("shareholders verification failed: inconsistent matrices");
            }
        }
    }

    fn prepare_dealers(
        threshold: u8,
        dealing_phase: bool,
        n: usize,
        rng: &mut impl RngCore,
    ) -> Vec<Dealer> {
        (0..n)
            .map(|_| Dealer::create(threshold, dealing_phase, rng).unwrap())
            .collect()
    }

    #[test]
    fn test_handoff() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let threshold = 2;

        // Handoff 0: Dealing phase.
        let kind = HandoffKind::DealingPhase;
        let committee = prepare_shareholders(&[1, 2, 3, 4]); // At least 4 (threshold + 2).
        let dealers = prepare_dealers(threshold, true, committee.len(), &mut rng);
        let mut handoffs = Vec::with_capacity(committee.len());

        for alice in committee.iter() {
            let handoff = Handoff::new(threshold, alice.clone(), committee.clone(), kind).unwrap();

            // Proactivization.
            for (j, (bob, dealer)) in zip(committee.iter(), dealers.iter()).enumerate() {
                let share = dealer.make_share(alice.clone(), kind);
                let vm = dealer.verification_matrix().clone();
                let verifiable_share = VerifiableSecretShare::new(share, vm);

                assert!(handoff.needs_bivariate_share(bob).unwrap());
                let done = handoff.add_bivariate_share(bob, verifiable_share).unwrap();

                if j + 1 < dealers.len() {
                    // Proactivization still in progress.
                    assert!(!done);
                    assert!(!handoff.needs_bivariate_share(bob).unwrap());
                } else {
                    // Proactivization done.
                    assert!(done);
                    assert!(handoff.needs_bivariate_share(bob).is_err());
                }
            }

            handoffs.push(handoff);
        }

        // Extract and verify shareholders.
        let mut shareholders = Vec::with_capacity(committee.len());
        for handoff in handoffs.iter() {
            // Share reduction should be skipped.
            assert!(handoff.get_reduced_shareholder().is_err());

            // Full share distribution should be completed.
            let shareholder = handoff.get_full_shareholder().unwrap();
            shareholders.push(shareholder);
        }

        verify_shareholders(&shareholders, threshold, true);

        // Handoff 1: Committee remains unchanged.
        let kind = HandoffKind::CommitteeUnchanged;
        let dealers = prepare_dealers(threshold, false, committee.len(), &mut rng);
        let mut handoffs = Vec::with_capacity(committee.len());

        for (i, alice) in committee.iter().enumerate() {
            let handoff = Handoff::new(
                threshold,
                alice.clone(),
                committee.clone(),
                HandoffKind::CommitteeUnchanged,
            )
            .unwrap();

            let shareholder = shareholders.get(i).unwrap().clone();

            assert!(handoff.needs_shareholder().unwrap());
            handoff.set_shareholder(shareholder).unwrap();

            // Proactivization.
            for (j, (bob, dealer)) in zip(committee.iter(), dealers.iter()).enumerate() {
                let share = dealer.make_share(alice.clone(), kind);
                let vm = dealer.verification_matrix().clone();
                let verifiable_share = VerifiableSecretShare::new(share, vm);

                assert!(handoff.needs_bivariate_share(&bob).unwrap());
                let done = handoff.add_bivariate_share(&bob, verifiable_share).unwrap();

                if j + 1 < dealers.len() {
                    // Proactivization still in progress.
                    assert!(!done);
                    assert!(!handoff.needs_bivariate_share(&bob).unwrap());
                } else {
                    // Proactivization done.
                    assert!(done);
                    assert!(handoff.needs_bivariate_share(&bob).is_err());
                }
            }

            handoffs.insert(i, handoff);
        }

        // Extract and verify shareholders.
        let mut shareholders = Vec::with_capacity(committee.len());
        for handoff in handoffs.iter() {
            // Share reduction should be skipped.
            assert!(handoff.get_reduced_shareholder().is_err());

            // Full share distribution should be completed.
            let shareholder = handoff.get_full_shareholder().unwrap();
            shareholders.push(shareholder);
        }

        verify_shareholders(&shareholders, threshold, true);

        // Handoff 2: Committee changed.
        let kind = HandoffKind::CommitteeChanged;
        let committee = prepare_shareholders(&[3, 4, 5, 6, 7]); // At least 5 (2 * threshold + 1).
        let dealers = prepare_dealers(threshold, false, committee.len(), &mut rng);
        let mut handoffs = Vec::with_capacity(committee.len());

        for alice in committee.iter() {
            let handoff = Handoff::new(
                threshold,
                alice.clone(),
                committee.clone(),
                HandoffKind::CommitteeChanged,
            )
            .unwrap();

            // Fetch verification matrix from the old committee.
            assert!(handoff.needs_verification_matrix().unwrap());
            let vm = shareholders[0]
                .verifiable_share()
                .verification_matrix()
                .clone();
            handoff.set_verification_matrix(vm).unwrap();

            // Share reduction.
            let num_points = threshold as usize + 1;
            for (j, shareholder) in shareholders.iter().take(num_points).enumerate() {
                let bob = shareholder.verifiable_share().share.x;

                assert!(handoff.needs_share_reduction_switch_point(&bob).unwrap());
                let bij = shareholder.switch_point(alice);
                let done = handoff
                    .add_share_reduction_switch_point(bob.clone(), bij)
                    .unwrap();

                if j + 1 < num_points {
                    // Accumulation still in progress.
                    assert!(!done);
                    assert!(!handoff.needs_share_reduction_switch_point(&bob).unwrap());
                } else {
                    // Accumulation done.
                    assert!(done);
                    assert!(handoff.needs_share_reduction_switch_point(&bob).is_err());
                }
            }

            // Proactivization.
            for (j, (bob, dealer)) in zip(committee.iter(), dealers.iter()).enumerate() {
                let share = dealer.make_share(alice.clone(), kind);
                let vm = dealer.verification_matrix().clone();
                let verifiable_share = VerifiableSecretShare::new(share, vm);

                assert!(handoff.needs_bivariate_share(&bob).unwrap());
                let done = handoff.add_bivariate_share(&bob, verifiable_share).unwrap();

                if j + 1 < dealers.len() {
                    // Proactivization still in progress.
                    assert!(!done);
                    assert!(!handoff.needs_bivariate_share(&bob).unwrap());
                } else {
                    // Proactivization done.
                    assert!(done);
                    assert!(handoff.needs_bivariate_share(&bob).is_err());
                }
            }

            handoffs.push(handoff);
        }

        // Extract and verify reduced shareholders.
        let mut shareholders = Vec::with_capacity(committee.len());
        for handoff in handoffs.iter() {
            // Share reduction should be completed.
            let shareholder = handoff.get_reduced_shareholder().unwrap();
            shareholders.push(shareholder);

            // Full share distribution hasn't started.
            assert!(handoff.get_full_shareholder().is_err());
        }

        verify_shareholders(&shareholders, threshold, false);

        for (alice, handoff) in zip(committee.iter(), handoffs.iter()) {
            // Share distribution.
            let num_points = 2 * threshold as usize + 1;
            for (j, shareholder) in shareholders.iter().take(num_points).enumerate() {
                let bob = shareholder.verifiable_share().share.x;

                assert!(handoff
                    .needs_full_share_distribution_switch_point(&bob)
                    .unwrap());
                let bij = shareholder.switch_point(&alice);
                let done = handoff
                    .add_full_share_distribution_switch_point(bob.clone(), bij)
                    .unwrap();

                if j + 1 < num_points {
                    // Accumulation still in progress.
                    assert!(!done);
                    assert!(!handoff
                        .needs_full_share_distribution_switch_point(&bob)
                        .unwrap());
                } else {
                    // Accumulation done.
                    assert!(done);
                    assert!(handoff
                        .needs_full_share_distribution_switch_point(&bob)
                        .is_err());
                }
            }
        }

        // Extract and verify full shareholders.
        let mut shareholders = Vec::with_capacity(committee.len());
        for handoff in handoffs.iter() {
            // Full share distribution should be completed.
            let shareholder = handoff.get_full_shareholder().unwrap();
            shareholders.push(shareholder);
        }

        verify_shareholders(&shareholders, threshold, true);
    }
}
