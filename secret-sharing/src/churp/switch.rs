use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use anyhow::Result;

use crate::vss::{
    lagrange::lagrange, matrix::VerificationMatrix, polynomial::Polynomial,
    vector::VerificationVector,
};

use super::{DealerParams, Error, HandoffKind, Player, Shareholder};

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

/// Dimension switch state.
enum DimensionSwitchState<D>
where
    D: DealerParams,
{
    /// Represents the state where the dimension switch is waiting for
    /// the verification matrix from the previous switch, which is needed
    /// to verify switch points. Once the matrix is received, the state
    /// transitions to the Accumulating state.
    WaitingForVerificationMatrix,

    /// Represents the state where the switch points are being accumulated.
    /// Upon collection of enough points, the state transitions to the Merging
    /// state if proactivization is required, or directly to the Serving state.
    Accumulating(SwitchPoints<D>),

    /// Represents the state where the dimension switch is waiting for a player
    /// to be proactivized with bivariate shares. The player can be constructed
    /// from received switch points, transferred from a previous handoff, or
    /// omitted if we want to construct a new one.
    WaitingForPlayer,

    /// Represents the state where the dimension switch is merging bivariate
    /// shares. Once enough shares are collected, the player is proactivized,
    /// and the state transitions to the Serving state. If no player was
    /// given, the combined shares define a new one.
    Merging(BivariateShares<D>),

    /// Represents the state where the dimension switch is completed,
    /// and a new player is available to serve requests.
    Serving(Arc<Player<D>>),
}

/// A dimension switch based on a share resharing technique.
pub struct DimensionSwitch<D>
where
    D: DealerParams,
{
    /// The degree of the secret-sharing polynomial.
    threshold: u8,

    /// The kind of handoff.
    handoff: HandoffKind,

    /// The kind of dimension switch.
    kind: DimensionSwitchKind,

    /// The encoded identity.
    me: D::PrimeField,

    /// The set of shareholders from which bivariate shares need to be fetched.
    /// If empty, proactivization is skipped.
    shareholders: HashSet<Shareholder>,

    /// Current state of the switch.
    state: Mutex<DimensionSwitchState<D>>,
}

impl<D> DimensionSwitch<D>
where
    D: DealerParams,
{
    /// Creates a new share reduction dimension switch.
    pub(crate) fn new_share_reduction(
        threshold: u8,
        me: Shareholder,
        shareholders: HashSet<Shareholder>,
        handoff: HandoffKind,
    ) -> Result<Self> {
        let kind = DimensionSwitchKind::ShareReduction;
        Self::new(threshold, me, shareholders, kind, handoff)
    }

    /// Creates a new full share distribution dimension switch.
    pub(crate) fn new_full_share_distribution(
        threshold: u8,
        me: Shareholder,
        shareholders: HashSet<Shareholder>,
        handoff: HandoffKind,
    ) -> Result<Self> {
        let kind = DimensionSwitchKind::FullShareDistribution;
        Self::new(threshold, me, shareholders, kind, handoff)
    }

    /// Creates a new dimension switch.
    fn new(
        threshold: u8,
        me: Shareholder,
        shareholders: HashSet<Shareholder>,
        kind: DimensionSwitchKind,
        handoff: HandoffKind,
    ) -> Result<Self> {
        let me = D::encode_shareholder(me)?;
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

        *state = DimensionSwitchState::WaitingForPlayer;
        Ok(())
    }

    /// Starts accumulating switch points using the provided verification
    /// matrix for point verification.
    pub(crate) fn start_accumulating(&self, vm: VerificationMatrix<D::Group>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match *state {
            DimensionSwitchState::WaitingForVerificationMatrix => (),
            _ => return Err(Error::InvalidState.into()),
        }

        let sp = SwitchPoints::new(self.threshold, &self.me, vm, self.kind)?;
        *state = DimensionSwitchState::Accumulating(sp);

        Ok(())
    }

    /// Checks if a switch point is required from the given shareholder.
    pub(crate) fn needs_switch_point(&self, id: &Shareholder) -> Result<bool> {
        let state = self.state.lock().unwrap();
        let sp = match &*state {
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
    pub(crate) fn add_switch_point(&self, id: Shareholder, bij: D::PrimeField) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let sp = match &mut *state {
            DimensionSwitchState::Accumulating(sp) => sp,
            _ => return Err(Error::InvalidState.into()),
        };

        let done = sp.add_point(id, bij)?;
        if done {
            let player = sp.reconstruct_player()?;
            let player = Arc::new(player);

            if self.shareholders.is_empty() {
                *state = DimensionSwitchState::Serving(player);
            } else {
                let bs = BivariateShares::new(
                    self.threshold,
                    self.me,
                    self.shareholders.clone(),
                    self.kind,
                    self.handoff,
                    Some(player),
                )?;
                *state = DimensionSwitchState::Merging(bs);
            }
        }

        Ok(done)
    }

    /// Checks if the switch is waiting for a player.
    pub(crate) fn is_waiting_for_player(&self) -> bool {
        let state = self.state.lock().unwrap();
        matches!(&*state, DimensionSwitchState::WaitingForPlayer)
    }

    /// Starts merging bivariate shares to be used for proactivization
    /// of the provided player.
    pub(crate) fn start_merging(&self, player: Option<Arc<Player<D>>>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        match &*state {
            DimensionSwitchState::WaitingForPlayer => (),
            _ => return Err(Error::InvalidState.into()),
        };

        let bs = BivariateShares::new(
            self.threshold,
            self.me,
            self.shareholders.clone(),
            self.kind,
            self.handoff,
            player,
        )?;
        *state = DimensionSwitchState::Merging(bs);

        Ok(())
    }

    /// Checks if a bivariate share is needed from the given shareholder.
    pub(crate) fn needs_bivariate_share(&self, id: &Shareholder) -> Result<bool> {
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
        id: Shareholder,
        q: Polynomial<<D as DealerParams>::PrimeField>,
        vm: VerificationMatrix<<D as DealerParams>::Group>,
    ) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let shares = match &mut *state {
            DimensionSwitchState::Merging(bs) => bs,
            _ => return Err(Error::InvalidState.into()),
        };

        let done = shares.add_bivariate_share(id, q, vm)?;
        if done {
            let player = shares.proactivize_player()?;
            let player = Arc::new(player);
            *state = DimensionSwitchState::Serving(player);
        }

        Ok(done)
    }

    /// Returns the player if the switch has completed.
    pub(crate) fn get_player(&self) -> Result<Arc<Player<D>>> {
        let state = self.state.lock().unwrap();
        let player = match &*state {
            DimensionSwitchState::Serving(p) => p.clone(),
            _ => return Err(Error::InvalidState.into()),
        };

        Ok(player)
    }
}

/// An accumulator for switch points.
#[derive(Debug)]
pub struct SwitchPoints<D>
where
    D: DealerParams,
{
    /// The minimum number of distinct points required to reconstruct
    /// the polynomial.
    n: usize,

    /// The verification matrix for the bivariate polynomial of the source
    /// committee from the previous handoff.
    ///
    /// It is used to validate incoming switch points `B(node_id, me)`
    /// or `B(me, node_id)` during the share reduction or full share
    /// distribution phase.
    vm: Option<VerificationMatrix<D::Group>>,

    /// The verification vector, derived from the verification matrix,
    /// is used to efficiently validate switch points.
    ///
    /// The vector can verify switch points from univariate polynomials
    /// `B(x, me)` or `B(me, y)` during the share reduction or full share
    /// distribution phase.
    vv: VerificationVector<D::Group>,

    /// A set of shareholders whose points have been received.
    shareholders: HashSet<Shareholder>,

    /// A list of encoded shareholders' identities whose points have been
    /// received.
    xs: Vec<D::PrimeField>,

    /// A list of received switch points.
    bijs: Vec<D::PrimeField>,
}

impl<D> SwitchPoints<D>
where
    D: DealerParams,
{
    /// Creates a new accumulator for switch points.
    fn new(
        threshold: u8,
        me: &D::PrimeField,
        vm: VerificationMatrix<D::Group>,
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
                let vv = vm.verification_vector_for_x(me);
                let n = rows;
                (n, vv)
            }
            DimensionSwitchKind::FullShareDistribution => {
                let vv = vm.verification_vector_for_y(me);
                let n = cols;
                (n, vv)
            }
        };

        // Wrap the matrix in an option so that we can take it when creating
        // a player.
        let vm = Some(vm);

        // We need at least n points to reconstruct the polynomial share.
        let shareholders = HashSet::with_capacity(n);
        let xs = Vec::with_capacity(n);
        let bijs = Vec::with_capacity(n);

        Ok(Self {
            n,
            vm,
            vv,
            shareholders,
            xs,
            bijs,
        })
    }

    /// Checks if a switch point is required from the given shareholder.
    fn needs_point(&self, id: &Shareholder) -> bool {
        if self.shareholders.len() >= self.n {
            return false;
        }
        !self.shareholders.contains(id)
    }

    /// Verifies and adds the given switch point.
    ///
    /// Returns true if enough points have been received; otherwise,
    /// it returns false.
    fn add_point(&mut self, id: Shareholder, bij: D::PrimeField) -> Result<bool> {
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
        let x = D::encode_shareholder(id)?;
        if !self.vv.verify(&x, &bij) {
            return Err(Error::InvalidSwitchPoint.into());
        }

        self.xs.push(x);
        self.bijs.push(bij);
        self.shareholders.insert(id);

        let done = self.shareholders.len() >= self.n;

        Ok(done)
    }

    /// Reconstructs the player from the received switch points.
    ///
    /// The player can be reconstructed only once, which avoids copying
    /// the verification matrix.
    fn reconstruct_player(&mut self) -> Result<Player<D>> {
        if self.shareholders.len() < self.n {
            return Err(Error::NotEnoughSwitchPoints.into());
        }

        let xs = &self.xs[0..self.n];
        let ys = &self.bijs[0..self.n];
        let p = lagrange(xs, ys);

        if p.degree() + 1 != self.n {
            return Err(Error::PolynomialDegreeMismatch.into());
        }

        let vm = self.vm.take().ok_or(Error::VerificationMatrixRequired)?;
        let player = Player::new(p, vm);

        Ok(player)
    }
}

/// An accumulator for bivariate shares.
struct BivariateShares<D>
where
    D: DealerParams,
{
    /// The degree of the secret-sharing polynomial.
    threshold: u8,

    /// Dimension switch kind.
    kind: DimensionSwitchKind,

    /// The encoded identity.
    me: D::PrimeField,

    /// The number of rows in the verification matrix.
    rows: usize,

    /// The number of columns in the verification matrix.
    cols: usize,

    /// Indicates whether bivariate shares should be derived from a zero-hole
    /// bivariate polynomial.
    zero_hole: bool,

    /// A set of shareholders providing bivariate shares.
    shareholders: HashSet<Shareholder>,
    /// A set of shareholders whose bivariate share still needs to be received.
    pending_shareholders: HashSet<Shareholder>,

    /// The sum of the received bivariate shares.
    p: Option<Polynomial<D::PrimeField>>,

    /// The sum of the verification matrices of the received bivariate shares.
    vm: Option<VerificationMatrix<D::Group>>,

    /// The player to be proactivized with bivariate shares.
    player: Option<Arc<Player<D>>>,
}

impl<D> BivariateShares<D>
where
    D: DealerParams,
{
    /// Creates a new accumulator for bivariate shares.
    fn new(
        threshold: u8,
        me: D::PrimeField,
        shareholders: HashSet<Shareholder>,
        kind: DimensionSwitchKind,
        handoff: HandoffKind,
        player: Option<Arc<Player<D>>>,
    ) -> Result<Self> {
        // During the dealing phase, the number of shares must be at least
        // threshold + 2, ensuring that even if t Byzantine dealers reveal
        // their secret, an honest player cannot compute the combined
        // bivariate polynomial.
        let min = match handoff {
            HandoffKind::DealingPhase => threshold as usize + 2,
            HandoffKind::CommitteeUnchanged => 1,
            HandoffKind::CommitteeChanged => 1,
        };
        if shareholders.len() < min {
            return Err(Error::NotEnoughShareholders.into());
        }

        let rows = threshold as usize + 1;
        let cols = 2 * threshold as usize + 1;
        let pending_shareholders = shareholders.clone();
        let zero_hole = handoff.require_zero_hole();

        Ok(Self {
            threshold,
            kind,
            me,
            rows,
            cols,
            zero_hole,
            shareholders,
            pending_shareholders,
            p: None,
            vm: None,
            player,
        })
    }

    /// Checks if a bivariate share is needed from the given shareholder.
    fn needs_bivariate_share(&self, id: &Shareholder) -> bool {
        self.pending_shareholders.contains(id)
    }

    /// Verifies and adds the given bivariate share.
    ///
    /// Returns true if all shares have been received; otherwise,
    /// it returns false.
    fn add_bivariate_share(
        &mut self,
        id: Shareholder,
        q: Polynomial<D::PrimeField>,
        vm: VerificationMatrix<D::Group>,
    ) -> Result<bool> {
        if !self.shareholders.contains(&id) {
            return Err(Error::UnknownShareholder.into());
        }
        if !self.pending_shareholders.contains(&id) {
            return Err(Error::DuplicateShareholder.into());
        }

        if vm.is_zero_hole() != self.zero_hole {
            return Err(Error::VerificationMatrixZeroHoleMismatch.into());
        }
        if vm.dimensions() != (self.rows, self.cols) {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }

        match self.kind {
            DimensionSwitchKind::ShareReduction => {
                if q.degree() != self.threshold as usize {
                    return Err(Error::PolynomialDegreeMismatch.into());
                }
                if !vm.verify_y(&self.me, &q) {
                    return Err(Error::InvalidPolynomial.into());
                }
            }
            DimensionSwitchKind::FullShareDistribution => {
                if q.degree() != 2 * self.threshold as usize {
                    return Err(Error::PolynomialDegreeMismatch.into());
                }
                if !vm.verify_x(&self.me, &q) {
                    return Err(Error::InvalidPolynomial.into());
                }
            }
        }

        let p = match self.p.take() {
            Some(p) => p + q,
            None => q,
        };
        self.p = Some(p);

        let vm = match self.vm.take() {
            Some(m) => m + vm,
            None => vm,
        };
        self.vm = Some(vm);

        self.pending_shareholders.remove(&id);
        let done = self.pending_shareholders.is_empty();

        Ok(done)
    }

    /// Proactivizes the player with the combined polynomial and verification
    /// matrix.
    fn proactivize_player(&mut self) -> Result<Player<D>> {
        if !self.pending_shareholders.is_empty() {
            return Err(Error::NotEnoughBivariateShares.into());
        }

        // The values cannot be empty since the constructor verifies that
        // the number of shareholders is greater than zero.
        let p = self.p.take().unwrap();
        let vm = self.vm.take().unwrap();

        let player = match &self.player {
            Some(player) => player.proactivize(&p, &vm)?,
            None => Player::new(p, vm),
        };

        Ok(player)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::Result;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        churp::{DealerParams, HandoffKind, NistP384, Shareholder},
        vss::{matrix::VerificationMatrix, polynomial::BivariatePolynomial},
    };

    use super::{BivariateShares, DimensionSwitchKind, Error, SwitchPoints};

    fn shareholder(id: u8) -> Shareholder {
        Shareholder([id; 32])
    }

    fn shareholders(ids: Vec<u8>) -> Vec<Shareholder> {
        ids.into_iter().map(shareholder).collect()
    }

    fn add_point(
        me: u8,
        sh: u8,
        bp: &BivariatePolynomial<p384::Scalar>,
        sp: &mut SwitchPoints<NistP384>,
        kind: DimensionSwitchKind,
    ) -> Result<bool> {
        let me = shareholder(me);
        let sh = shareholder(sh);
        let x = NistP384::encode_shareholder(sh).unwrap();
        let y = NistP384::encode_shareholder(me).unwrap();
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
        let me = NistP384::encode_shareholder(shareholder(1)).unwrap();

        for kind in vec![
            DimensionSwitchKind::ShareReduction,
            DimensionSwitchKind::FullShareDistribution,
        ] {
            let mut sp = SwitchPoints::<NistP384>::new(threshold, &me, vm.clone(), kind).unwrap();
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
            let res = sp.reconstruct_player();
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
            let res = sp.reconstruct_player();
            assert!(res.is_ok());
        }
    }

    fn add_bivariate_shares(
        threshold: u8,
        me: u8,
        sh: u8,
        bs: &mut BivariateShares<NistP384>,
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
        let x = NistP384::encode_shareholder(me).unwrap();
        let q = match dkind {
            DimensionSwitchKind::ShareReduction => bp.eval_y(&x),
            DimensionSwitchKind::FullShareDistribution => bp.eval_x(&x),
        };
        bs.add_bivariate_share(sh, q, vm)
    }

    #[test]
    fn test_bivariate_shares() {
        let threshold = 2;
        let hkind = HandoffKind::CommitteeChanged;

        let me = NistP384::encode_shareholder(shareholder(1)).unwrap();
        let shs = shareholders(vec![1, 2, 3]);
        let shareholders: HashSet<Shareholder> = shs.iter().cloned().collect();

        // Dealing phase requires at least threshold + 2 dealers.
        let res = BivariateShares::<NistP384>::new(
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
            let mut bs = BivariateShares::<NistP384>::new(
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
            let res = bs.proactivize_player();
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
            let res = bs.proactivize_player();
            assert!(res.is_ok());
        }
    }
}
