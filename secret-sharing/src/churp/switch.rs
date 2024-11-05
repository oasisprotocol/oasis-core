use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use group::{ff::PrimeField, Group};
use zeroize::Zeroize;

use crate::{
    poly::{lagrange::lagrange, Point},
    vss::{VerificationMatrix, VerificationVector},
};

use super::{Error, SecretShare, Shareholder, VerifiableSecretShare};

/// A simple wrapper around point that is zeroized when dropped.
pub struct SwitchPoint<F>(Point<F>)
where
    F: PrimeField + Zeroize;

impl<F> SwitchPoint<F>
where
    F: PrimeField + Zeroize,
{
    /// Creates a new switch point.
    pub fn new(x: F, y: F) -> Self {
        Self(Point::new(x, y))
    }
}

impl<F> Deref for SwitchPoint<F>
where
    F: PrimeField + Zeroize,
{
    type Target = Point<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> Zeroize for SwitchPoint<F>
where
    F: PrimeField + Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<F> Drop for SwitchPoint<F>
where
    F: PrimeField + Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Dimension switch state.
enum DimensionSwitchState<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// Represents the state where the dimension switch is waiting for
    /// the verification matrix from the previous switch, which is needed
    /// to verify switch points. Once the matrix is received, the state
    /// transitions to the Accumulating state.
    WaitingForVerificationMatrix,

    /// Represents the state where the switch points are being accumulated.
    /// Upon collection of enough points, the state transitions to the Merging
    /// state if proactivization is required, or directly to the Serving state.
    Accumulating(SwitchPoints<G>),

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
    Merging(BivariateShares<G>),

    /// Represents the state where the dimension switch is completed,
    /// and a new shareholder is available to serve requests.
    Serving(Arc<Shareholder<G>>),
}

/// A dimension switch based on a share resharing technique.
pub struct DimensionSwitch<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// The degree of the secret-sharing polynomial.
    threshold: u8,

    /// Indicates whether bivariate shares should be derived from a zero-hole
    /// bivariate polynomial.
    zero_hole: bool,

    /// Indicates whether bivariate shares should be full or reduced shares.
    full_share: bool,

    /// The encoded identity.
    me: G::Scalar,

    /// The set of shareholders from which bivariate shares need to be fetched.
    /// If empty, proactivization is skipped.
    shareholders: Vec<G::Scalar>,

    /// Current state of the switch.
    state: Mutex<DimensionSwitchState<G>>,
}

impl<G> DimensionSwitch<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// Creates a new share reduction dimension switch.
    ///
    /// In share reduction, shareholders switch from the degree-t dimension
    /// of the secret bivariate polynomial B(x,y) to the degree-2t dimension.
    /// As a result, each shareholders in the new committee obtains a reduced
    /// share B(x,j) and proactivizes it to B'(x,j).
    pub(crate) fn new_share_reduction(
        threshold: u8,
        zero_hole: bool,
        me: G::Scalar,
        shareholders: Vec<G::Scalar>,
    ) -> Result<Self> {
        Self::new(threshold, zero_hole, false, me, shareholders)
    }

    /// Creates a new full share distribution dimension switch.
    ///
    /// In full share distribution, new shares B'(i,y) are generated from
    /// proactive reduced shares, by switching back to the degree-t dimension
    /// of B'(x,y).
    pub(crate) fn new_full_share_distribution(
        threshold: u8,
        zero_hole: bool,
        me: G::Scalar,
        shareholders: Vec<G::Scalar>,
    ) -> Result<Self> {
        Self::new(threshold, zero_hole, true, me, shareholders)
    }

    /// Creates a new dimension switch.
    fn new(
        threshold: u8,
        zero_hole: bool,
        full_share: bool,
        me: G::Scalar,
        shareholders: Vec<G::Scalar>,
    ) -> Result<Self> {
        let state = Mutex::new(DimensionSwitchState::WaitingForVerificationMatrix);

        Ok(Self {
            threshold,
            zero_hole,
            full_share,
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
    pub(crate) fn start_accumulating(&self, vm: VerificationMatrix<G>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match *state {
            DimensionSwitchState::WaitingForVerificationMatrix => (),
            _ => return Err(Error::InvalidState.into()),
        }

        let sp = SwitchPoints::new(self.threshold, self.full_share, self.me, vm)?;
        *state = DimensionSwitchState::Accumulating(sp);

        Ok(())
    }

    /// Checks if a switch point is required from the given shareholder.
    pub(crate) fn needs_switch_point(&self, x: &G::Scalar) -> Result<bool> {
        let state = self.state.lock().unwrap();
        let sp = match &*state {
            DimensionSwitchState::WaitingForVerificationMatrix => return Ok(true),
            DimensionSwitchState::Accumulating(sp) => sp,
            _ => return Err(Error::InvalidState.into()),
        };

        let needs = sp.needs_point(x);
        Ok(needs)
    }

    /// Verifies and adds the given switch point.
    ///
    /// Returns true if enough points have been received and the switch
    /// transitioned to the next state.
    pub(crate) fn add_switch_point(&self, point: SwitchPoint<G::Scalar>) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let sp = match &mut *state {
            DimensionSwitchState::Accumulating(sp) => sp,
            _ => return Err(Error::InvalidState.into()),
        };

        sp.add_point(point)?;

        if sp.needs_points() {
            return Ok(false);
        }

        let shareholder = sp.reconstruct_shareholder()?;
        let shareholder = Arc::new(shareholder);

        if self.shareholders.is_empty() {
            *state = DimensionSwitchState::Serving(shareholder);
        } else {
            let bs = BivariateShares::new(
                self.threshold,
                self.zero_hole,
                self.full_share,
                self.me,
                self.shareholders.clone(),
                Some(shareholder),
            )?;
            *state = DimensionSwitchState::Merging(bs);
        }

        Ok(true)
    }

    /// Checks if the switch is waiting for a shareholder.
    pub(crate) fn is_waiting_for_shareholder(&self) -> bool {
        let state = self.state.lock().unwrap();
        matches!(&*state, DimensionSwitchState::WaitingForShareholder)
    }

    /// Starts merging bivariate shares to be used for proactivization
    /// of the provided shareholder.
    pub(crate) fn start_merging(&self, shareholder: Option<Arc<Shareholder<G>>>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            DimensionSwitchState::WaitingForShareholder => (),
            _ => return Err(Error::InvalidState.into()),
        };

        let bs = BivariateShares::new(
            self.threshold,
            self.zero_hole,
            self.full_share,
            self.me,
            self.shareholders.clone(),
            shareholder,
        )?;
        *state = DimensionSwitchState::Merging(bs);

        Ok(())
    }

    /// Checks if a bivariate share is needed from the given shareholder.
    pub(crate) fn needs_bivariate_share(&self, x: &G::Scalar) -> Result<bool> {
        let state = self.state.lock().unwrap();
        let bs = match &*state {
            DimensionSwitchState::Merging(bs) => bs,
            _ => return Err(Error::InvalidState.into()),
        };

        let needs = bs.needs_bivariate_share(x);
        Ok(needs)
    }

    /// Verifies and adds the given bivariate share.
    ///
    /// Returns true if all shares have been received and the switch
    /// transitioned to the next state.
    pub(crate) fn add_bivariate_share(
        &self,
        x: &G::Scalar,
        verifiable_share: VerifiableSecretShare<G>,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let shares = match &mut *state {
            DimensionSwitchState::Merging(bs) => bs,
            _ => return Err(Error::InvalidState.into()),
        };

        let done = shares.add_bivariate_share(x, verifiable_share)?;
        if done {
            let shareholder = shares.proactivize_shareholder()?;
            let shareholder = Arc::new(shareholder);
            *state = DimensionSwitchState::Serving(shareholder);
        }

        Ok(done)
    }

    /// Returns the shareholder if the switch has completed.
    pub(crate) fn get_shareholder(&self) -> Result<Arc<Shareholder<G>>> {
        let state = self.state.lock().unwrap();
        let shareholder = match &*state {
            DimensionSwitchState::Serving(p) => p.clone(),
            _ => return Err(Error::InvalidState.into()),
        };

        Ok(shareholder)
    }
}

/// An accumulator for switch points.
pub struct SwitchPoints<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// The minimum number of distinct points required to reconstruct
    /// the polynomial.
    n: usize,

    /// Field element representing the identity of the shareholder.
    me: Option<G::Scalar>,

    /// The verification matrix for the bivariate polynomial of the source
    /// committee from the previous handoff.
    ///
    /// It is used to validate incoming switch points `B(node_id, me)`
    /// or `B(me, node_id)` during the share reduction or full share
    /// distribution phase.
    vm: Option<VerificationMatrix<G>>,

    /// The verification vector, derived from the verification matrix,
    /// is used to efficiently validate switch points.
    ///
    /// The vector can verify switch points from univariate polynomials
    /// `B(x, me)` or `B(me, y)` during the share reduction or full share
    /// distribution phase.
    vv: VerificationVector<G>,

    /// A list of received switch points.
    points: Vec<SwitchPoint<G::Scalar>>,
}

impl<G> SwitchPoints<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// Creates a new accumulator for switch points.
    fn new(
        threshold: u8,
        full_share: bool,
        me: G::Scalar,
        vm: VerificationMatrix<G>,
    ) -> Result<Self> {
        let threshold = threshold as usize;
        let rows = threshold + 1;
        let cols = 2 * threshold + 1;

        if vm.dimensions() != (rows, cols) {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }

        // Precomputing the verification vector speeds up switch point
        // validation.
        let (n, vv) = match full_share {
            false => (rows, vm.verification_vector_for_x(&me)),
            true => (cols, vm.verification_vector_for_y(&me)),
        };

        // Wrap the identifier and the matrix in an option so that we can take
        // them when creating a shareholder.
        let me = Some(me);
        let vm = Some(vm);

        // We need at least n points to reconstruct the polynomial share.
        let points = Vec::with_capacity(n);

        Ok(Self {
            n,
            me,
            vm,
            vv,
            points,
        })
    }

    /// Checks if a switch point has already been received from the given shareholder.
    fn has_point(&self, x: &G::Scalar) -> bool {
        self.points.iter().any(|p| &p.x == x)
    }

    /// Checks if a switch point is required from the given shareholder.
    fn needs_point(&self, x: &G::Scalar) -> bool {
        self.needs_points() && !self.has_point(x)
    }

    /// Checks if additional switch points are needed.
    fn needs_points(&self) -> bool {
        self.points.len() < self.n
    }

    /// Verifies and adds the given switch point.
    ///
    /// Returns true if enough points have been received; otherwise,
    /// it returns false.
    fn add_point(&mut self, point: SwitchPoint<G::Scalar>) -> Result<()> {
        if self.points.len() >= self.n {
            return Err(Error::TooManySwitchPoints.into());
        }
        if self.has_point(&point.x) {
            return Err(Error::DuplicateShareholder.into());
        }

        // The identity of the shareholder doesn't require verification.
        // If the point is valid, it doesn't matter if it came from a stranger.
        // However, since verification is costly, one could check if the point
        // came from a legitimate shareholder.
        if !self.vv.verify(&point.x, &point.y) {
            return Err(Error::InvalidSwitchPoint.into());
        }

        self.points.push(point);

        Ok(())
    }

    /// Reconstructs the shareholder from the received switch points.
    ///
    /// The shareholder can be reconstructed only once, which avoids copying
    /// the verification matrix.
    fn reconstruct_shareholder(&mut self) -> Result<Shareholder<G>> {
        if self.points.len() < self.n {
            return Err(Error::NotEnoughSwitchPoints.into());
        }

        let points: Vec<_> = self.points[0..self.n].iter().map(|p| &p.0).collect();
        let p = lagrange(&points);
        let x = self.me.take().ok_or(Error::ShareholderIdentityRequired)?;
        let vm = self.vm.take().ok_or(Error::VerificationMatrixRequired)?;
        let share: SecretShare<<G as Group>::Scalar> = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        let shareholder: Shareholder<G> = verifiable_share.into();

        if shareholder.verifiable_share().polynomial().size() != self.n {
            return Err(Error::PolynomialDegreeMismatch.into());
        }

        Ok(shareholder)
    }
}

/// An accumulator for bivariate shares.
struct BivariateShares<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// The degree of the secret-sharing polynomial.
    threshold: u8,

    /// Indicates whether bivariate shares should be derived from a zero-hole
    /// bivariate polynomial.
    zero_hole: bool,

    /// Indicates whether bivariate shares should be full or reduced shares.
    full_share: bool,

    /// Field element representing the identity of the shareholder.
    me: G::Scalar,

    /// A set of shareholders providing bivariate shares.
    shareholders: Vec<G::Scalar>,

    /// A set of shareholders whose bivariate share still needs to be received.
    pending_shareholders: Vec<G::Scalar>,

    /// The shareholder to be proactivized with bivariate shares.
    shareholder: Option<Arc<Shareholder<G>>>,

    /// The sum of the received verifiable bivariate shares.
    combined_share: Option<VerifiableSecretShare<G>>,
}

impl<G> BivariateShares<G>
where
    G: Group,
    G::Scalar: Zeroize,
{
    /// Creates a new accumulator for bivariate shares.
    fn new(
        threshold: u8,
        zero_hole: bool,
        full_share: bool,
        me: G::Scalar,
        shareholders: Vec<G::Scalar>,
        shareholder: Option<Arc<Shareholder<G>>>,
    ) -> Result<Self> {
        if shareholders.is_empty() {
            return Err(Error::NotEnoughShareholders.into());
        }

        let pending_shareholders = shareholders.clone();

        Ok(Self {
            threshold,
            zero_hole,
            full_share,
            me,
            shareholders,
            pending_shareholders,
            shareholder,
            combined_share: None,
        })
    }

    /// Checks if a bivariate share can be received from the given shareholder.
    fn has_bivariate_share(&self, x: &G::Scalar) -> bool {
        self.shareholders.contains(x)
    }

    /// Checks if a bivariate share is needed from the given shareholder.
    fn needs_bivariate_share(&self, x: &G::Scalar) -> bool {
        self.pending_shareholders.contains(x)
    }

    /// Verifies and adds the given bivariate share.
    ///
    /// Returns true if all shares have been received; otherwise,
    /// it returns false.
    fn add_bivariate_share(
        &mut self,
        x: &G::Scalar,
        verifiable_share: VerifiableSecretShare<G>,
    ) -> Result<bool> {
        if !self.has_bivariate_share(x) {
            return Err(Error::UnknownShareholder.into());
        }
        if !self.needs_bivariate_share(x) {
            return Err(Error::DuplicateShareholder.into());
        }

        if verifiable_share.x() != &self.me {
            return Err(Error::ShareholderIdentityMismatch.into());
        }
        verifiable_share.verify(self.threshold, self.zero_hole, self.full_share)?;

        if let Some(ref mut cs) = self.combined_share {
            *cs += &verifiable_share;
        } else {
            self.combined_share = Some(verifiable_share);
        }

        let index = self
            .pending_shareholders
            .iter()
            .position(|y| y == x)
            .unwrap();
        self.pending_shareholders.swap_remove(index);

        let done = self.pending_shareholders.is_empty();

        Ok(done)
    }

    /// Proactivizes the shareholder with the combined polynomial
    /// and verification matrix.
    fn proactivize_shareholder(&mut self) -> Result<Shareholder<G>> {
        if !self.pending_shareholders.is_empty() {
            return Err(Error::NotEnoughBivariateShares.into());
        }

        let verifiable_share = self
            .combined_share
            .take()
            .ok_or(Error::ShareholderProactivizationCompleted)?;

        let shareholder = match &self.shareholder {
            Some(shareholder) => {
                shareholder.proactivize(&verifiable_share.p, &verifiable_share.vm)?
            }
            None => verifiable_share.into(),
        };

        // Ensure that the combined bivariate polynomial satisfies
        // the non-zero leading term requirements.
        shareholder
            .verifiable_share()
            .verify(self.threshold, false, self.full_share)?;

        Ok(shareholder)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        churp::{SecretShare, VerifiableSecretShare},
        poly::{self},
        suites::{self, p384},
        vss,
    };

    use super::{BivariateShares, Error, SwitchPoint, SwitchPoints};

    type Suite = p384::Sha3_384;
    type Group = <Suite as suites::Suite>::Group;
    type PrimeField = <Suite as suites::Suite>::PrimeField;
    type BivariatePolynomial = poly::BivariatePolynomial<<Suite as suites::Suite>::PrimeField>;
    type VerificationMatrix = vss::VerificationMatrix<<Suite as suites::Suite>::Group>;

    fn prepare_shareholder(id: u64) -> PrimeField {
        id.into()
    }

    fn prepare_shareholders(ids: &[u64]) -> Vec<PrimeField> {
        ids.into_iter().map(|&id| id.into()).collect()
    }

    fn add_point(
        me: u64,
        sh: u64,
        bp: &BivariatePolynomial,
        sp: &mut SwitchPoints<Group>,
        full_share: bool,
    ) -> Result<bool> {
        let x = prepare_shareholder(sh);
        let y = prepare_shareholder(me);
        let bij = match full_share {
            false => bp.eval(&x, &y),
            true => bp.eval(&y, &x),
        };
        let point = SwitchPoint::new(x, bij);
        sp.add_point(point)?;
        Ok(!sp.needs_points())
    }

    #[test]
    fn test_switch_point() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let threshold = 2;
        let deg_x = threshold;
        let deg_y = 2 * threshold;
        let bp = BivariatePolynomial::random(deg_x, deg_y, &mut rng);
        let vm = VerificationMatrix::from(&bp);
        let me = prepare_shareholder(1);

        for full_share in vec![false, true] {
            let mut sp = SwitchPoints::<Group>::new(threshold, full_share, me, vm.clone()).unwrap();
            let me = 1;
            let mut sh = 2;

            // Add invalid point (switch x and y).
            let res = add_point(sh, me, &bp, &mut sp, full_share);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::InvalidSwitchPoint.to_string()
            );

            // Add point.
            let res = add_point(me, me, &bp, &mut sp, full_share);
            assert!(res.is_ok());
            assert!(!res.unwrap());

            // Add another point twice.
            assert!(sp.needs_point(&prepare_shareholder(sh)));

            let res = add_point(me, sh, &bp, &mut sp, full_share);
            assert!(res.is_ok());
            assert!(!res.unwrap());

            let res = add_point(me, sh, &bp, &mut sp, full_share);
            assert!(res.is_err());
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::DuplicateShareholder.to_string()
            );

            assert!(!sp.needs_point(&prepare_shareholder(sh)));
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
            if full_share {
                for _ in 0..threshold {
                    let res = add_point(me, sh, &bp, &mut sp, full_share);
                    assert!(res.is_ok());
                    assert!(!res.unwrap());
                    sh += 1;
                }
            }

            // Add the last point.
            let res = add_point(me, sh, &bp, &mut sp, full_share);
            assert!(res.is_ok());
            assert!(res.unwrap()); // Enough points.
            sh += 1;

            // No more points needed.
            assert!(!sp.needs_point(&prepare_shareholder(sh)));

            // Too many points.
            let res = add_point(me, sh, &bp, &mut sp, full_share);
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
        zero_hole: bool,
        full_share: bool,
        me: u64,
        sh: u64,
        bs: &mut BivariateShares<Group>,
    ) -> Result<bool> {
        let deg_x = threshold;
        let deg_y = 2 * threshold;
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut bp = BivariatePolynomial::random(deg_x, deg_y, &mut rng);
        if zero_hole {
            bp.to_zero_hole();
        };
        let vm = VerificationMatrix::from(&bp);
        let x = prepare_shareholder(me);
        let p = match full_share {
            false => bp.eval_y(&x),
            true => bp.eval_x(&x),
        };
        let share = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        let x = prepare_shareholder(sh);
        bs.add_bivariate_share(&x, verifiable_share)
    }

    #[test]
    fn test_bivariate_shares() {
        let threshold = 2;

        let me = prepare_shareholder(1);
        let shareholders = prepare_shareholders(&[1, 2, 3]);

        // There should be at least 1 shareholder.
        let res = BivariateShares::<Group>::new(threshold, false, false, me, vec![], None);
        assert!(res.is_err());
        unsafe {
            assert_eq!(
                res.unwrap_err_unchecked().to_string(),
                Error::NotEnoughShareholders.to_string()
            );
        }

        // Happy path.
        for full_share in vec![false, true] {
            for zero_hole in vec![false, true] {
                let mut bs = BivariateShares::<Group>::new(
                    threshold,
                    zero_hole,
                    full_share,
                    me,
                    shareholders.clone(),
                    None,
                )
                .unwrap();

                let me = 1;
                let mut sh = 2;

                // Add invalid share (invalid threshold).
                let res =
                    add_bivariate_shares(threshold + 1, zero_hole, full_share, me, me, &mut bs);
                assert!(res.is_err());
                assert_eq!(
                    res.unwrap_err().to_string(),
                    Error::VerificationMatrixDimensionMismatch.to_string()
                );

                // Add share.
                let res = add_bivariate_shares(threshold, zero_hole, full_share, me, me, &mut bs);
                assert!(res.is_ok());
                assert!(!res.unwrap());

                // Add another share twice.
                assert!(bs.needs_bivariate_share(&prepare_shareholder(sh)));

                let res = add_bivariate_shares(threshold, zero_hole, full_share, me, sh, &mut bs);
                assert!(res.is_ok());
                assert!(!res.unwrap());

                let res = add_bivariate_shares(threshold, zero_hole, full_share, me, sh, &mut bs);
                assert!(res.is_err());
                assert_eq!(
                    res.unwrap_err().to_string(),
                    Error::DuplicateShareholder.to_string()
                );

                assert!(!bs.needs_bivariate_share(&prepare_shareholder(sh)));
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
                let res = add_bivariate_shares(threshold, zero_hole, full_share, me, sh, &mut bs);
                assert!(res.is_ok());
                assert!(res.unwrap()); // Enough shares.
                sh += 1;

                // Unknown shareholder.
                assert!(!bs.needs_bivariate_share(&prepare_shareholder(sh)));

                let res = add_bivariate_shares(threshold, zero_hole, full_share, me, sh, &mut bs);
                assert!(res.is_err());
                assert_eq!(
                    res.unwrap_err().to_string(),
                    Error::UnknownShareholder.to_string()
                );

                // Try to collect the polynomial and verification matrix again.
                let res = bs.proactivize_shareholder();
                match zero_hole {
                    true => assert!(res.is_err()), // The combined polynomial has zero secret (not allowed).
                    false => assert!(res.is_ok()), // The combined polynomial has non-zero secret.
                }
            }
        }
    }
}
