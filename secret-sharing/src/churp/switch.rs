use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use anyhow::Result;

use crate::{
    suites::Suite,
    vss::{
        lagrange::lagrange, matrix::VerificationMatrix, polynomial::Polynomial,
        vector::VerificationVector,
    },
};

use super::{Error, HandoffKind, SecretShare, Shareholder, ShareholderId, VerifiableSecretShare};

/// Dimension switch kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DimensionSwitchKind {
    /// In share reduction, shareholders switch from the degree-t dimension
    /// of the secret bivariate polynomial B(x,y) to the degree-2t dimension.
    /// As a result, each shareholders in the new committee obtains a reduced
    /// share B(x,j) and proactivizes it to B'(x,j).
    ShareReduction,
    /// In full share distribution, new shares B'(i,y) are generated from
    /// proactive reduced shares, by switching back to the degree-t dimension
    /// of B'(x,y).
    FullShareDistribution,
}

impl DimensionSwitchKind {
    /// Indicates whether bivariate shares should be full or reduced shares.
    pub fn require_full_shares(&self) -> bool {
        match &self {
            DimensionSwitchKind::ShareReduction => false,
            DimensionSwitchKind::FullShareDistribution => true,
        }
    }
}

/// Dimension switch state.
enum DimensionSwitchState<S>
where
    S: Suite,
{
    /// Represents the state where the dimension switch is waiting for
    /// the verification matrix from the previous switch, which is needed
    /// to verify switch points. Once the matrix is received, the state
    /// transitions to the Accumulating state.
    WaitingForVerificationMatrix,

    /// Represents the state where the switch points are being accumulated.
    /// Upon collection of enough points, the state transitions to the Merging
    /// state if proactivization is required, or directly to the Serving state.
    Accumulating(SwitchPoints<S>),

    /// Represents the state where the dimension switch is waiting
    /// for a shareholder to be proactivized with bivariate shares.
    /// The shareholder can be constructed from received switch points,
    /// transferred from a previous handoff, or omitted if we want
    /// to construct a new one.
    WaitingForShareholder,

    /// Represents the state where the dimension switch is merging
    /// bivariate shares. Once enough shares are collected, the shareholder
    /// is proactivized, and the state transitions to the Serving state.
    /// If no shareholder was given, the combined shares define a new one.
    Merging(BivariateShares<S>),

    /// Represents the state where the dimension switch is completed,
    /// and a new shareholder is available to serve requests.
    Serving(Arc<Shareholder<S::Group>>),
}

/// A dimension switch based on a share resharing technique.
pub struct DimensionSwitch<S>
where
    S: Suite,
{
    /// The degree of the secret-sharing polynomial.
    threshold: u8,

    /// The kind of handoff.
    handoff: HandoffKind,

    /// The kind of dimension switch.
    kind: DimensionSwitchKind,

    /// The encoded identity.
    me: S::PrimeField,

    /// The set of shareholders from which bivariate shares need to be fetched.
    /// If empty, proactivization is skipped.
    shareholders: HashSet<ShareholderId>,

    /// Current state of the switch.
    state: Mutex<DimensionSwitchState<S>>,
}

impl<S> DimensionSwitch<S>
where
    S: Suite,
{
    /// Creates a new share reduction dimension switch.
    pub(crate) fn new_share_reduction(
        threshold: u8,
        me: ShareholderId,
        shareholders: HashSet<ShareholderId>,
        handoff: HandoffKind,
    ) -> Result<Self> {
        let kind = DimensionSwitchKind::ShareReduction;
        Self::new(threshold, me, shareholders, kind, handoff)
    }

    /// Creates a new full share distribution dimension switch.
    pub(crate) fn new_full_share_distribution(
        threshold: u8,
        me: ShareholderId,
        shareholders: HashSet<ShareholderId>,
        handoff: HandoffKind,
    ) -> Result<Self> {
        let kind = DimensionSwitchKind::FullShareDistribution;
        Self::new(threshold, me, shareholders, kind, handoff)
    }

    /// Creates a new dimension switch.
    fn new(
        threshold: u8,
        me: ShareholderId,
        shareholders: HashSet<ShareholderId>,
        kind: DimensionSwitchKind,
        handoff: HandoffKind,
    ) -> Result<Self> {
        let me = me.encode::<S>()?;
        let state = Mutex::new(DimensionSwitchState::WaitingForVerificationMatrix);

        Ok(Self {
            threshold,
            kind,
            handoff,
            me,
            shareholders,
            state,
        })
    }

    /// Checks if the switch is waiting for the verification matrix.
    pub(crate) fn is_waiting_for_verification_matrix(&self) -> bool {
        let state = self.state.lock().unwrap();
        matches!(&*state, DimensionSwitchState::WaitingForVerificationMatrix)
    }

    /// Skips the switch point accumulation.
    pub(crate) fn skip_accumulating(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            DimensionSwitchState::WaitingForVerificationMatrix => (),
            _ => return Err(Error::InvalidState.into()),
        };

        *state = DimensionSwitchState::WaitingForShareholder;
        Ok(())
    }

    /// Starts accumulating switch points using the provided verification
    /// matrix for point verification.
    pub(crate) fn start_accumulating(&self, vm: VerificationMatrix<S::Group>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match *state {
            DimensionSwitchState::WaitingForVerificationMatrix => (),
            _ => return Err(Error::InvalidState.into()),
        }

        let sp = SwitchPoints::new(self.threshold, self.me, vm, self.kind)?;
        *state = DimensionSwitchState::Accumulating(sp);

        Ok(())
    }

    /// Checks if a switch point is required from the given shareholder.
    pub(crate) fn needs_switch_point(&self, id: &ShareholderId) -> Result<bool> {
        let state = self.state.lock().unwrap();
        let sp = match &*state {
            DimensionSwitchState::WaitingForVerificationMatrix => return Ok(true),
            DimensionSwitchState::Accumulating(sp) => sp,
            _ => return Err(Error::InvalidState.into()),
        };

        let needs = sp.needs_point(id);
        Ok(needs)
    }

    /// Verifies and adds the given switch point.
    ///
    /// Returns true if enough points have been received and the switch
    /// transitioned to the next state.
    pub(crate) fn add_switch_point(&self, id: ShareholderId, bij: S::PrimeField) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let sp = match &mut *state {
            DimensionSwitchState::Accumulating(sp) => sp,
            _ => return Err(Error::InvalidState.into()),
        };

        let done = sp.add_point(id, bij)?;
        if done {
            let shareholder = sp.reconstruct_shareholder()?;
            let shareholder = Arc::new(shareholder);

            if self.shareholders.is_empty() {
                *state = DimensionSwitchState::Serving(shareholder);
            } else {
                let bs = BivariateShares::new(
                    self.threshold,
                    self.me,
                    self.shareholders.clone(),
                    self.kind,
                    self.handoff,
                    Some(shareholder),
                )?;
                *state = DimensionSwitchState::Merging(bs);
            }
        }

        Ok(done)
    }

    /// Checks if the switch is waiting for a shareholder.
    pub(crate) fn is_waiting_for_shareholder(&self) -> bool {
        let state = self.state.lock().unwrap();
        matches!(&*state, DimensionSwitchState::WaitingForShareholder)
    }

    /// Starts merging bivariate shares to be used for proactivization
    /// of the provided shareholder.
    pub(crate) fn start_merging(
        &self,
        shareholder: Option<Arc<Shareholder<S::Group>>>,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            DimensionSwitchState::WaitingForShareholder => (),
            _ => return Err(Error::InvalidState.into()),
        };

        let bs = BivariateShares::new(
            self.threshold,
            self.me,
            self.shareholders.clone(),
            self.kind,
            self.handoff,
            shareholder,
        )?;
        *state = DimensionSwitchState::Merging(bs);

        Ok(())
    }

    /// Checks if a bivariate share is needed from the given shareholder.
    pub(crate) fn needs_bivariate_share(&self, id: &ShareholderId) -> Result<bool> {
        let state = self.state.lock().unwrap();
        let bs = match &*state {
            DimensionSwitchState::Merging(bs) => bs,
            _ => return Err(Error::InvalidState.into()),
        };

        let needs = bs.needs_bivariate_share(id);
        Ok(needs)
    }

    /// Verifies and adds the given bivariate share.
    ///
    /// Returns true if all shares have been received and the switch
    /// transitioned to the next state.
    pub(crate) fn add_bivariate_share(
        &self,
        id: ShareholderId,
        verifiable_share: VerifiableSecretShare<S::Group>,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let shares = match &mut *state {
            DimensionSwitchState::Merging(bs) => bs,
            _ => return Err(Error::InvalidState.into()),
        };

        let done = shares.add_bivariate_share(id, verifiable_share)?;
        if done {
            let shareholder = shares.proactivize_shareholder()?;
            let shareholder = Arc::new(shareholder);
            *state = DimensionSwitchState::Serving(shareholder);
        }

        Ok(done)
    }

    /// Returns the shareholder if the switch has completed.
    pub(crate) fn get_shareholder(&self) -> Result<Arc<Shareholder<S::Group>>> {
        let state = self.state.lock().unwrap();
        let shareholder = match &*state {
            DimensionSwitchState::Serving(p) => p.clone(),
            _ => return Err(Error::InvalidState.into()),
        };

        Ok(shareholder)
    }
}

/// An accumulator for switch points.
#[derive(Debug)]
pub struct SwitchPoints<S>
where
    S: Suite,
{
    /// The minimum number of distinct points required to reconstruct
    /// the polynomial.
    n: usize,

    /// Field element representing the identity of the shareholder.
    me: Option<S::PrimeField>,

    /// The verification matrix for the bivariate polynomial of the source
    /// committee from the previous handoff.
    ///
    /// It is used to validate incoming switch points `B(node_id, me)`
    /// or `B(me, node_id)` during the share reduction or full share
    /// distribution phase.
    vm: Option<VerificationMatrix<S::Group>>,

    /// The verification vector, derived from the verification matrix,
    /// is used to efficiently validate switch points.
    ///
    /// The vector can verify switch points from univariate polynomials
    /// `B(x, me)` or `B(me, y)` during the share reduction or full share
    /// distribution phase.
    vv: VerificationVector<S::Group>,

    /// A set of shareholders whose points have been received.
    shareholders: HashSet<ShareholderId>,

    /// A list of encoded shareholders' identities whose points have been
    /// received.
    xs: Vec<S::PrimeField>,

    /// A list of received switch points.
    bijs: Vec<S::PrimeField>,
}

impl<S> SwitchPoints<S>
where
    S: Suite,
{
    /// Creates a new accumulator for switch points.
    fn new(
        threshold: u8,
        me: S::PrimeField,
        vm: VerificationMatrix<S::Group>,
        kind: DimensionSwitchKind,
    ) -> Result<Self> {
        let threshold = threshold as usize;
        let rows = threshold + 1;
        let cols = 2 * threshold + 1;

        if vm.dimensions() != (rows, cols) {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }

        // Precomputing the verification vector speeds up switch point
        // validation.
        let (n, vv) = match kind {
            DimensionSwitchKind::ShareReduction => {
                let vv = vm.verification_vector_for_x(&me);
                let n = rows;
                (n, vv)
            }
            DimensionSwitchKind::FullShareDistribution => {
                let vv = vm.verification_vector_for_y(&me);
                let n = cols;
                (n, vv)
            }
        };

        // Wrap the identifier and the matrix in an option so that we can take
        // them when creating a shareholder.
        let me = Some(me);
        let vm = Some(vm);

        // We need at least n points to reconstruct the polynomial share.
        let shareholders = HashSet::with_capacity(n);
        let xs = Vec::with_capacity(n);
        let bijs = Vec::with_capacity(n);

        Ok(Self {
            n,
            me,
            vm,
            vv,
            shareholders,
            xs,
            bijs,
        })
    }

    /// Checks if a switch point is required from the given shareholder.
    fn needs_point(&self, id: &ShareholderId) -> bool {
        if self.shareholders.len() >= self.n {
            return false;
        }
        !self.shareholders.contains(id)
    }

    /// Verifies and adds the given switch point.
    ///
    /// Returns true if enough points have been received; otherwise,
    /// it returns false.
    fn add_point(&mut self, id: ShareholderId, bij: S::PrimeField) -> Result<bool> {
        if self.shareholders.len() >= self.n {
            return Err(Error::TooManySwitchPoints.into());
        }
        if self.shareholders.contains(&id) {
            return Err(Error::DuplicateShareholder.into());
        }

        // The identity of the shareholder doesn't require verification.
        // If the point is valid, it doesn't matter if it came from a stranger.
        // However, since verification is costly, one could check if the point
        // came from a legitimate shareholder.
        let x = id.encode::<S>()?;
        if !self.vv.verify(&x, &bij) {
            return Err(Error::InvalidSwitchPoint.into());
        }

        self.xs.push(x);
        self.bijs.push(bij);
        self.shareholders.insert(id);

        let done = self.shareholders.len() >= self.n;

        Ok(done)
    }

    /// Reconstructs the shareholder from the received switch points.
    ///
    /// The shareholder can be reconstructed only once, which avoids copying
    /// the verification matrix.
    fn reconstruct_shareholder(&mut self) -> Result<Shareholder<S::Group>> {
        if self.shareholders.len() < self.n {
            return Err(Error::NotEnoughSwitchPoints.into());
        }

        let xs = &self.xs[0..self.n];
        let ys = &self.bijs[0..self.n];
        let p = lagrange(xs, ys);

        if p.degree() + 1 != self.n {
            return Err(Error::PolynomialDegreeMismatch.into());
        }

        let x = self.me.take().ok_or(Error::ShareholderIdentityRequired)?;
        let vm = self.vm.take().ok_or(Error::VerificationMatrixRequired)?;
        let share = SecretShare::new(x, p);
        let shareholder = Shareholder::new(share, vm);

        Ok(shareholder)
    }
}

/// An accumulator for bivariate shares.
struct BivariateShares<S>
where
    S: Suite,
{
    /// The degree of the secret-sharing polynomial.
    threshold: u8,

    /// Field element representing the identity of the shareholder.
    me: S::PrimeField,

    /// Indicates whether bivariate shares should be derived from a zero-hole
    /// bivariate polynomial.
    zero_hole: bool,

    /// Indicates whether bivariate shares should be full or reduced shares.
    full_share: bool,

    /// A set of shareholders providing bivariate shares.
    shareholders: HashSet<ShareholderId>,
    /// A set of shareholders whose bivariate share still needs to be received.
    pending_shareholders: HashSet<ShareholderId>,

    /// The sum of the received bivariate shares.
    p: Option<Polynomial<S::PrimeField>>,

    /// The sum of the verification matrices of the received bivariate shares.
    vm: Option<VerificationMatrix<S::Group>>,

    /// The shareholder to be proactivized with bivariate shares.
    shareholder: Option<Arc<Shareholder<S::Group>>>,
}

impl<S> BivariateShares<S>
where
    S: Suite,
{
    /// Creates a new accumulator for bivariate shares.
    fn new(
        threshold: u8,
        me: S::PrimeField,
        shareholders: HashSet<ShareholderId>,
        kind: DimensionSwitchKind,
        handoff: HandoffKind,
        shareholder: Option<Arc<Shareholder<S::Group>>>,
    ) -> Result<Self> {
        // During the dealing phase, the number of shares must be at least
        // threshold + 2, ensuring that even if t Byzantine dealers reveal
        // their secret, an honest shareholder cannot compute the combined
        // bivariate polynomial.
        let min = match handoff {
            HandoffKind::DealingPhase => threshold as usize + 2,
            HandoffKind::CommitteeUnchanged => 1,
            HandoffKind::CommitteeChanged => 1,
        };
        if shareholders.len() < min {
            return Err(Error::NotEnoughShareholders.into());
        }

        let pending_shareholders = shareholders.clone();
        let zero_hole = handoff.require_zero_hole();
        let full_share = kind.require_full_shares();

        Ok(Self {
            threshold,
            me,
            zero_hole,
            full_share,
            shareholders,
            pending_shareholders,
            p: None,
            vm: None,
            shareholder,
        })
    }

    /// Checks if a bivariate share is needed from the given shareholder.
    fn needs_bivariate_share(&self, id: &ShareholderId) -> bool {
        self.pending_shareholders.contains(id)
    }

    /// Verifies and adds the given bivariate share.
    ///
    /// Returns true if all shares have been received; otherwise,
    /// it returns false.
    fn add_bivariate_share(
        &mut self,
        id: ShareholderId,
        verifiable_share: VerifiableSecretShare<S::Group>,
    ) -> Result<bool> {
        if !self.shareholders.contains(&id) {
            return Err(Error::UnknownShareholder.into());
        }
        if !self.pending_shareholders.contains(&id) {
            return Err(Error::DuplicateShareholder.into());
        }

        if verifiable_share.share.x != self.me {
            return Err(Error::ShareholderIdentityMismatch.into());
        }
        verifiable_share.verify(self.threshold, self.zero_hole, self.full_share)?;

        let p = match self.p.take() {
            Some(p) => p + verifiable_share.share.p,
            None => verifiable_share.share.p,
        };
        self.p = Some(p);

        let vm = match self.vm.take() {
            Some(vm) => vm + verifiable_share.vm,
            None => verifiable_share.vm,
        };
        self.vm = Some(vm);

        self.pending_shareholders.remove(&id);
        let done = self.pending_shareholders.is_empty();

        Ok(done)
    }

    /// Proactivizes the shareholder with the combined polynomial
    /// and verification matrix.
    fn proactivize_shareholder(&mut self) -> Result<Shareholder<S::Group>> {
        if !self.pending_shareholders.is_empty() {
            return Err(Error::NotEnoughBivariateShares.into());
        }

        // The values cannot be empty since the constructor verifies that
        // the number of shareholders is greater than zero.
        let p = self.p.take().unwrap();
        let vm = self.vm.take().unwrap();

        let shareholder = match &self.shareholder {
            Some(shareholder) => shareholder.proactivize(&p, &vm)?,
            None => {
                let share = SecretShare::new(self.me, p);
                Shareholder::new(share, vm)
            }
        };

        Ok(shareholder)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::Result;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        churp::{HandoffKind, SecretShare, ShareholderId, VerifiableSecretShare},
        suites::{self, p384},
        vss::{matrix, polynomial},
    };

    use super::{BivariateShares, DimensionSwitchKind, Error, SwitchPoints};

    type Suite = p384::Sha3_384;
    type BivariatePolynomial =
        polynomial::BivariatePolynomial<<Suite as suites::Suite>::PrimeField>;
    type VerificationMatrix = matrix::VerificationMatrix<<Suite as suites::Suite>::Group>;

    fn shareholder(id: u8) -> ShareholderId {
        ShareholderId([id; 32])
    }

    fn shareholders(ids: Vec<u8>) -> Vec<ShareholderId> {
        ids.into_iter().map(shareholder).collect()
    }

    fn add_point(
        me: u8,
        sh: u8,
        bp: &BivariatePolynomial,
        sp: &mut SwitchPoints<Suite>,
        kind: DimensionSwitchKind,
    ) -> Result<bool> {
        let me = shareholder(me);
        let sh = shareholder(sh);
        let x = sh.encode::<Suite>().unwrap();
        let y = me.encode::<Suite>().unwrap();
        let bij = match kind {
            DimensionSwitchKind::ShareReduction => bp.eval(&x, &y),
            DimensionSwitchKind::FullShareDistribution => bp.eval(&y, &x),
        };
        let res = sp.add_point(sh, bij);
        res
    }

    #[test]
    fn test_switch_point() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let threshold = 2;
        let deg_x = threshold;
        let deg_y = 2 * threshold;
        let bp = BivariatePolynomial::random(deg_x, deg_y, &mut rng);
        let vm = VerificationMatrix::from(&bp);
        let me = shareholder(1).encode::<Suite>().unwrap();

        for kind in vec![
            DimensionSwitchKind::ShareReduction,
            DimensionSwitchKind::FullShareDistribution,
        ] {
            let mut sp = SwitchPoints::<Suite>::new(threshold, me, vm.clone(), kind).unwrap();
            let me = 1;
            let mut sh = 2;

            // Add invalid point (switch x and y).
            let res = add_point(sh, me, &bp, &mut sp, kind);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::InvalidSwitchPoint.to_string()
            );

            // Add point.
            let res = add_point(me, me, &bp, &mut sp, kind);
            assert!(res.is_ok());
            assert!(!res.unwrap());

            // Add another point twice.
            assert!(sp.needs_point(&shareholder(sh)));

            let res = add_point(me, sh, &bp, &mut sp, kind);
            assert!(res.is_ok());
            assert!(!res.unwrap());

            let res = add_point(me, sh, &bp, &mut sp, kind);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::DuplicateShareholder.to_string()
            );

            assert!(!sp.needs_point(&shareholder(sh)));
            sh += 1;

            // Try to reconstruct the polynomial.
            let res = sp.reconstruct_shareholder();
            assert!(res.is_err());
            unsafe {
                assert_eq!(
                    res.unwrap_err_unchecked().to_string(),
                    Error::NotEnoughSwitchPoints.to_string()
                );
            }

            // Full share distribution needs 2 * threshold points.
            if kind == DimensionSwitchKind::FullShareDistribution {
                for _ in 0..threshold {
                    let res = add_point(me, sh, &bp, &mut sp, kind);
                    assert!(res.is_ok());
                    assert!(!res.unwrap());
                    sh += 1;
                }
            }

            // Add the last point.
            let res = add_point(me, sh, &bp, &mut sp, kind);
            assert!(res.is_ok());
            assert!(res.unwrap()); // Enough points.
            sh += 1;

            // No more points needed.
            assert!(!sp.needs_point(&shareholder(sh)));

            // Too many points.
            let res = add_point(me, sh, &bp, &mut sp, kind);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::TooManySwitchPoints.to_string()
            );

            // Try to reconstruct the polynomial again.
            let res = sp.reconstruct_shareholder();
            assert!(res.is_ok());
        }
    }

    fn add_bivariate_shares(
        threshold: u8,
        me: u8,
        sh: u8,
        bs: &mut BivariateShares<Suite>,
        dkind: DimensionSwitchKind,
        hkind: HandoffKind,
    ) -> Result<bool> {
        let deg_x = threshold;
        let deg_y = 2 * threshold;
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut bp = BivariatePolynomial::random(deg_x, deg_y, &mut rng);
        if hkind.require_zero_hole() {
            bp.to_zero_hole();
        };
        let vm = VerificationMatrix::from(&bp);
        let me = shareholder(me);
        let sh = shareholder(sh);
        let x = me.encode::<Suite>().unwrap();
        let p = match dkind {
            DimensionSwitchKind::ShareReduction => bp.eval_y(&x),
            DimensionSwitchKind::FullShareDistribution => bp.eval_x(&x),
        };
        let share = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        bs.add_bivariate_share(sh, verifiable_share)
    }

    #[test]
    fn test_bivariate_shares() {
        let threshold = 2;
        let hkind = HandoffKind::CommitteeChanged;

        let me = shareholder(1).encode::<Suite>().unwrap();
        let shs = shareholders(vec![1, 2, 3]);
        let shareholders: HashSet<ShareholderId> = shs.iter().cloned().collect();

        // Dealing phase requires at least threshold + 2 dealers.
        let res = BivariateShares::<Suite>::new(
            threshold,
            me,
            shareholders.clone(),
            DimensionSwitchKind::ShareReduction,
            HandoffKind::DealingPhase,
            None,
        );
        assert!(res.is_err());
        unsafe {
            assert_eq!(
                res.unwrap_err_unchecked().to_string(),
                Error::NotEnoughShareholders.to_string()
            );
        }

        // Happy path.
        for dkind in vec![
            DimensionSwitchKind::ShareReduction,
            DimensionSwitchKind::FullShareDistribution,
        ] {
            let mut bs = BivariateShares::<Suite>::new(
                threshold,
                me,
                shareholders.clone(),
                dkind,
                hkind,
                None,
            )
            .unwrap();

            let me = 1;
            let mut sh = 2;

            // Add invalid share (invalid threshold).
            let res = add_bivariate_shares(threshold + 1, me, me, &mut bs, dkind, hkind);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::VerificationMatrixDimensionMismatch.to_string()
            );

            // Add share.
            let res = add_bivariate_shares(threshold, me, me, &mut bs, dkind, hkind);
            assert!(res.is_ok());
            assert!(!res.unwrap());

            // Add another share twice.
            assert!(bs.needs_bivariate_share(&shareholder(sh)));

            let res = add_bivariate_shares(threshold, me, sh, &mut bs, dkind, hkind);
            assert!(res.is_ok());
            assert!(!res.unwrap());

            let res = add_bivariate_shares(threshold, me, sh, &mut bs, dkind, hkind);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::DuplicateShareholder.to_string()
            );

            assert!(!bs.needs_bivariate_share(&shareholder(sh)));
            sh += 1;

            // Try to collect the polynomial and verification matrix.
            let res = bs.proactivize_shareholder();
            assert!(res.is_err());
            unsafe {
                assert_eq!(
                    res.unwrap_err_unchecked().to_string(),
                    Error::NotEnoughBivariateShares.to_string()
                );
            }

            // Add the last share.
            let res = add_bivariate_shares(threshold, me, sh, &mut bs, dkind, hkind);
            assert!(res.is_ok());
            assert!(res.unwrap()); // Enough shares.
            sh += 1;

            // Unknown shareholder.
            assert!(!bs.needs_bivariate_share(&shareholder(sh)));

            let res = add_bivariate_shares(threshold, me, sh, &mut bs, dkind, hkind);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::UnknownShareholder.to_string()
            );

            // Try to collect the polynomial and verification matrix again.
            let res = bs.proactivize_shareholder();
            assert!(res.is_ok());
        }
    }
}
