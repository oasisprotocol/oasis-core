//! Key derivation center.

use std::iter::zip;

use anyhow::{bail, Result};
use group::{ff::PrimeField, Group};

use crate::{
    poly::{lagrange, EncryptedPoint},
    suites::GroupDigest,
};

/// A trait for shareholders which hold a secret share point on a secret-sharing
/// polynomial.
pub trait PointShareholder<F: PrimeField> {
    /// Returns the x-coordinate of the secret share point
    /// held by the shareholder.
    fn coordinate_x(&self) -> &F;

    /// Returns the y-coordinate of the secret share point
    /// held by the shareholder.
    fn coordinate_y(&self) -> &F;
}

/// A trait for shareholders capable of deriving key shares.
pub trait KeySharer<G: Group> {
    /// Derives a key share based on the given key ID and domain separation tag.
    fn make_key_share<H: GroupDigest<Output = G>>(
        &self,
        key_id: &[u8],
        dst: &[u8],
    ) -> Result<EncryptedPoint<G>>;
}

impl<G, S> KeySharer<G> for S
where
    G: Group,
    S: PointShareholder<G::Scalar>,
{
    fn make_key_share<H: GroupDigest<Output = G>>(
        &self,
        key_id: &[u8],
        dst: &[u8],
    ) -> Result<EncryptedPoint<G>> {
        let hash = H::hash_to_group(key_id, dst)?;
        let x = self.coordinate_x();
        let y = self.coordinate_y();
        let point = EncryptedPoint { x: *x, z: hash * y };
        Ok(point)
    }
}

/// A trait for recovering a secret key from key shares.
pub trait KeyRecoverer {
    /// Returns the minimum number of key shares required to recover
    /// the secret key.
    fn min_shares(&self) -> usize;

    /// Recovers the secret key from the provided key shares.
    fn recover_key<G: Group>(&self, shares: &[EncryptedPoint<G>]) -> Result<G> {
        if shares.len() < self.min_shares() {
            bail!("not enough shares");
        }
        if !Self::distinct_shares(shares) {
            bail!("not distinct shares");
        }

        let (xs, zs): (Vec<_>, Vec<_>) = shares.iter().map(|p| (p.x, p.z)).unzip();
        let cs = lagrange::coefficients(&xs);
        let key = zip(cs, zs).map(|(c, z)| z * c).sum();

        Ok(key)
    }

    /// Returns true if shares are from distinct shareholders.
    fn distinct_shares<G: Group>(shares: &[EncryptedPoint<G>]) -> bool {
        // For a small number of shareholders, a brute-force approach should
        // suffice, and it doesn't require the prime field to be hashable.
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                if shares[i].x == shares[j].x {
                    return false;
                }
            }
        }
        true
    }
}
