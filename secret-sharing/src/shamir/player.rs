use std::iter::zip;

use anyhow::{bail, Result};
use group::ff::PrimeField;

use crate::{
    kdc::KeyRecoverer,
    poly::{lagrange, Point},
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

    /// Returns true iff shares are from distinct shareholders.
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
        kdc::{KeyRecoverer, KeySharer},
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
        // Prepare parameters.
        let threshold = 2;
        let num_shareholders = 5;
        let secret = PrimeField::from_u64(100);

        // Prepare a player for secret recovery.
        let player = Player::new(threshold);
        let min_shares = player.min_shares();

        // Prepare a dealer and distribute shares to shareholders.
        let dealer = Dealer::new(threshold, secret, &mut OsRng);
        let shares = (1..=num_shareholders)
            .map(|x| dealer.make_share(PrimeField::from_u64(x)))
            .collect::<Vec<_>>();
        let shareholders = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect::<Vec<_>>();

        // Fetch shares.
        let shares = shareholders
            .iter()
            .map(|shareholder| shareholder.secret_share())
            .cloned()
            .collect::<Vec<_>>();

        // Recover the secret (exact number of shares).
        let recovered = player.recover_secret(&shares[0..min_shares]).unwrap();
        assert_eq!(secret, recovered);
        let recovered = player.recover_secret(&shares[2..min_shares + 2]).unwrap();
        assert_eq!(secret, recovered);

        // Recover the secret (too many shares).
        let recovered = player.recover_secret(&shares).unwrap();
        assert_eq!(secret, recovered);

        // Attempt to recover the secret (not enough shares).
        let result = player.recover_secret(&shares[0..min_shares - 1]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not enough shares");

        // Fetch duplicate shares.
        let shares = (0..min_shares)
            .map(|_| shareholders[0].secret_share())
            .cloned()
            .collect::<Vec<_>>();

        // Attempt to recover the secret (duplicate shares).
        let result = player.recover_secret(&shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not distinct shares");
    }

    #[test]
    fn test_kdc() {
        // Prepare parameters.
        let threshold = 2;
        let num_shareholders = 5;
        let secret = PrimeField::from_u64(100);

        // Compute the key.
        let key_id = b"key id";
        let dst = b"encode key share";
        let hash = Suite::hash_to_group(key_id, dst).unwrap();
        let key = hash * secret;

        // Prepare a player for key recovery.
        let player = Player::new(threshold);
        let min_shares = player.min_shares();

        // Prepare a dealer and distribute shares.
        let dealer: Dealer<::p384::Scalar> = Dealer::new(threshold, secret, &mut OsRng);
        let shares = (1..=num_shareholders)
            .map(|x| dealer.make_share(PrimeField::from_u64(x)))
            .collect::<Vec<_>>();
        let shareholders = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect::<Vec<_>>();

        // Fetch shares.
        let shares = shareholders
            .iter()
            .map(|shareholder| shareholder.make_key_share::<Suite>(key_id, dst).unwrap())
            .collect::<Vec<_>>();

        // Recover the key (exact number of shares).
        let recovered = player.recover_key(&shares[0..min_shares]).unwrap();
        assert_eq!(key, recovered);
        let recovered = player.recover_key(&shares[2..min_shares + 2]).unwrap();
        assert_eq!(key, recovered);

        // Recover the key (too many shares).
        let recovered = player.recover_key(&shares).unwrap();
        assert_eq!(key, recovered);

        // Attempt to recover the key (not enough shares).
        let result = player.recover_key(&shares[0..min_shares - 1]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not enough shares");

        // Fetch duplicate shares.
        let shares = (0..min_shares)
            .map(|_| {
                shareholders[0]
                    .make_key_share::<Suite>(key_id, dst)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // Attempt to recover the key (duplicate shares).
        let result = player.recover_key(&shares);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "not distinct shares");
    }

    #[test]
    fn test_proactivization() {
        // Prepare parameters.
        let threshold = 2;
        let num_dealers = 5;
        let num_shareholders = 5;
        let secret = PrimeField::from_u64(100);

        // Prepare a player for secret recovery.
        let player = Player::new(threshold);
        let min_shares = player.min_shares();

        // Prepare a dealer and distribute shares.
        let dealer = Dealer::new(threshold, secret, &mut OsRng);
        let shares = (1..=num_shareholders)
            .map(|x| dealer.make_share(PrimeField::from_u64(x)))
            .collect::<Vec<_>>();
        let mut shareholders = shares
            .into_iter()
            .map(|share| Shareholder::new(share))
            .collect::<Vec<_>>();

        // Fetch shares.
        let shares = shareholders
            .iter()
            .map(|shareholder| shareholder.secret_share())
            .cloned()
            .collect::<Vec<_>>();

        // Recover the secret.
        let recovered = player.recover_secret(&shares[0..min_shares]).unwrap();
        assert_eq!(secret, recovered);
        let recovered = player.recover_secret(&shares[2..min_shares + 2]).unwrap();
        assert_eq!(secret, recovered);

        // Prepare dealers of proactive shares.
        let dealers = (0..num_dealers)
            .map(|_| Dealer::new(threshold, PrimeField::ZERO, &mut OsRng))
            .collect::<Vec<_>>();

        // Proactivize shares.
        for shareholder in shareholders.iter_mut() {
            let proactive_shares = dealers
                .iter()
                .map(|dealer| dealer.make_share(shareholder.secret_share().x))
                .collect::<Vec<_>>();
            shareholder.proactivize(&proactive_shares).unwrap();
        }

        // Fetch shares.
        let new_shares = shareholders
            .iter()
            .map(|shareholder| shareholder.secret_share())
            .cloned()
            .collect::<Vec<_>>();

        // Recover the secret.
        let recovered = player.recover_secret(&new_shares[0..min_shares]).unwrap();
        assert_eq!(secret, recovered);
        let recovered = player
            .recover_secret(&new_shares[2..min_shares + 2])
            .unwrap();
        assert_eq!(secret, recovered);

        // Verify that the shares have changed (brute-force).
        for share in &shares {
            for new_share in &new_shares {
                if share.x == new_share.x {
                    assert_ne!(share.y, new_share.y, "share hasn't changed");
                }
            }
        }

        // Invalid proactive share.
        let proactive_share = dealers[0].make_share(shareholders[0].secret_share().x);
        let result = shareholders[1].proactivize(&[proactive_share]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invalid proactive share");
    }
}
