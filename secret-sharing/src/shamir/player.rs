use std::iter::zip;

use anyhow::{bail, Result};
use group::ff::PrimeField;

use crate::{
    kdc::KeyRecoverer,
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

    /// Recovers the secret from the provided shares.
    pub fn recover_secret<F: PrimeField>(&self, shares: &[Point<F>]) -> Result<F> {
        if shares.len() < self.min_shares() {
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

    /// Returns the minimum number of shares required to recover the secret.
    fn min_shares(&self) -> usize {
        self.threshold as usize + 1
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

impl KeyRecoverer for Player {
    fn min_shares(&self) -> usize {
        self.min_shares()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{
        kdc::{KeyRecoverer, KeySharer, KEY_ID_ENC_DST},
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
        let min_shares = player.min_shares() as u64;

        // Not enough shares.
        let n = min_shares - 1;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let result = player.recover_secret(&shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not enough shares");

        // Duplicate shares.
        let xs = (1..=n)
            .flat_map(|x| std::iter::repeat(x).take(2))
            .map(PrimeField::from_u64)
            .collect();
        let shares = dealer.make_shares(xs);
        let result = player.recover_secret(&shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not distinct shares");

        // Exact number of shares.
        let n = min_shares;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let recovered = player.recover_secret(&shares).unwrap();
        assert_eq!(secret, recovered);

        // Too many shares.
        let n = min_shares + 10;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let recovered = player.recover_secret(&shares).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_kdc() {
        // Prepare scheme.
        let threshold = 2;
        let key_id = b"key identifier";
        let dst = b"shamir secret sharing scheme";
        let secret = PrimeField::from_u64(100);
        let hash = Suite::hash_to_group(key_id, dst, KEY_ID_ENC_DST).unwrap();
        let key = hash * secret;
        let dealer = Dealer::new(threshold, secret, &mut OsRng);
        let player = Player::new(threshold);
        let min_shares = player.min_shares() as u64;

        // Not enough shares.
        let n = min_shares - 1;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.make_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let result = player.recover_key(&key_shares);
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
            .map(|sh| sh.make_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let result = player.recover_key(&key_shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not distinct shares");

        // Exact number of shares.
        let n = min_shares;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.make_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let recovered = player.recover_key(&key_shares).unwrap();
        assert_eq!(key, recovered);

        // Too many shares.
        let n = min_shares + 10;
        let xs = (1..=n).map(PrimeField::from_u64).collect();
        let shares = dealer.make_shares(xs);
        let shareholders: Vec<_> = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect();
        let key_shares: Vec<_> = shareholders
            .iter()
            .map(|sh| sh.make_key_share::<Suite>(key_id, dst).unwrap())
            .collect();
        let recovered = player.recover_key(&key_shares).unwrap();
        assert_eq!(key, recovered);
    }
}
