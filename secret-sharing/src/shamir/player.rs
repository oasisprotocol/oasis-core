use std::iter::zip;

use anyhow::{bail, Result};
use group::ff::PrimeField;

use crate::{
    kdc::KeyReconstructor,
    vss::{lagrange, polynomial::Point},
};

/// A constructor of the shared secret.
pub struct Player {
    threshold: u8,
}

impl Player {
    /// Creates a new player.
    pub fn new(threshold: u8) -> Self {
        Player { threshold }
    }

    /// Reconstructs the secret from the provided shares.
    pub fn reconstruct_secret<F: PrimeField>(&self, shares: &[Point<F>]) -> Result<F> {
        let required_shares = self.threshold as usize + 1;
        if shares.len() < required_shares {
            bail!("not enough shares");
        }
        if !Self::distinct_shares(shares) {
            bail!("not distinct shares");
        }

        let (xs, ys): (Vec<_>, Vec<_>) = shares.iter().map(|p| (p.x, p.y)).unzip();
        let cs = lagrange::coefficients(&xs);
        let secret = zip(cs, ys).map(|(c, y)| y * c).sum();

        Ok(secret)
    }

    /// Returns true if shares are from distinct shareholders.
    fn distinct_shares<F: PrimeField>(shares: &[Point<F>]) -> bool {
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

impl KeyReconstructor for Player {
    fn threshold(&self) -> u8 {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{
        kdc::{KeyReconstructor, KeySharer},
        shamir::{Dealer, Shareholder},
        suites::{self, p384, GroupDigest},
    };

    use super::Player;

    // Suite used in tests.
    type Suite = p384::Sha3_384;

    // Prime field used in tests.
    type PrimeField = <p384::Sha3_384 as suites::Suite>::PrimeField;

    #[test]
    fn test_shamir() {
        // Prepare scheme.
        let threshold = 2;
        let secret = PrimeField::from_u64(100);
        let dealer = Dealer::new(threshold, secret, &mut OsRng);
        let player = Player::new(threshold);

        // Not enough shares.
        let n = threshold as u64;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let result = player.reconstruct_secret(&shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not enough shares");

        // Duplicate shares.
        let xs = (1..=n)
            .flat_map(|x| std::iter::repeat(x).take(2))
            .map(PrimeField::from_u64)
            .collect();
        let shares = dealer.make_shares(xs);
        let result = player.reconstruct_secret(&shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not distinct shares");

        // Exact number of shares.
        let n = threshold as u64 + 1;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let reconstructed = player.reconstruct_secret(&shares).unwrap();
        assert_eq!(secret, reconstructed);

        // Too many shares.
        let n = threshold as u64 + 10;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let reconstructed = player.reconstruct_secret(&shares).unwrap();
        assert_eq!(secret, reconstructed);
    }

    #[test]
    fn test_kdc() {
        // Prepare scheme.
        let threshold = 2;
        let key_id = b"key identifier";
        let dst = b"shamir secret sharing scheme";
        let secret = PrimeField::from_u64(100);
        let hash = Suite::hash_to_group(key_id, dst).unwrap();
        let key = hash * secret;
        let dealer = Dealer::new(threshold, secret, &mut OsRng);
        let player = Player::new(threshold);

        // Not enough shares.
        let n = threshold as u64;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.derive_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let result = player.reconstruct_key(&key_shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not enough shares");

        // Duplicate shares.
        let xs = (1..=n)
            .flat_map(|x| std::iter::repeat(x).take(2))
            .map(PrimeField::from_u64)
            .collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.derive_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let result = player.reconstruct_key(&key_shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not distinct shares");

        // Exact number of shares.
        let n = threshold as u64 + 1;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.derive_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let reconstructed = player.reconstruct_key(&key_shares).unwrap();
        assert_eq!(key, reconstructed);

        // Too many shares.
        let n = threshold as u64 + 10;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.derive_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let reconstructed = player.reconstruct_key(&key_shares).unwrap();
        assert_eq!(key, reconstructed);
    }
}
