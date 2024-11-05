use anyhow::{bail, Result};
use group::ff::PrimeField;
use zeroize::Zeroize;

use crate::{kdc::KeyRecoverer, poly::lagrange};

use super::{HandoffKind, SecretShare};

/// A constructor of the shared secret.
pub struct Player {
    threshold: u8,
    kind: HandoffKind,
}

impl Player {
    /// Creates a new player.
    pub fn new(threshold: u8, kind: HandoffKind) -> Self {
        Player { threshold, kind }
    }

    /// Recovers the secret from the provided shares.
    pub fn recover_secret<F: PrimeField + Zeroize>(&self, shares: &[SecretShare<F>]) -> Result<F> {
        if shares.len() < self.min_shares() {
            bail!("not enough shares");
        }
        if !Self::distinct_shares(shares) {
            bail!("not distinct shares");
        }

        let xs = shares.iter().map(|s| *s.x()).collect::<Vec<_>>();
        let cs = lagrange::coefficients(&xs);
        let mut secret = F::ZERO;
        for (mut ci, share) in cs.into_iter().zip(shares) {
            ci *= share.y();
            secret += &ci;
            ci.zeroize();
        }

        Ok(secret)
    }

    /// Returns the minimum number of shares required to recover the secret.
    fn min_shares(&self) -> usize {
        let threshold = self.threshold as usize;
        if self.kind == HandoffKind::CommitteeChanged {
            return 2 * threshold + 1;
        }
        threshold + 1
    }

    /// Returns true if shares are from distinct shareholders.
    fn distinct_shares<F: PrimeField + Zeroize>(shares: &[SecretShare<F>]) -> bool {
        // For a small number of shareholders, a brute-force approach should
        // suffice, and it doesn't require the prime field to be hashable.
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                if shares[i].x() == shares[j].x() {
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
        churp::{self, HandoffKind, Shareholder, VerifiableSecretShare},
        kdc::{KeyRecoverer, KeySharer},
        suites::{self, p384, GroupDigest},
    };

    use super::Player;

    // Types used in tests.
    type Suite = p384::Sha3_384;
    type PrimeField = <Suite as suites::Suite>::PrimeField;
    type Group = <Suite as suites::Suite>::Group;
    type Dealer = churp::Dealer<Group>;

    #[test]
    fn test_churp() {
        let test_cases = vec![
            HandoffKind::DealingPhase,
            HandoffKind::CommitteeUnchanged,
            HandoffKind::CommitteeChanged,
        ];

        for kind in test_cases.into_iter() {
            // Prepare scheme.
            let threshold = 2;
            let secret = PrimeField::from_u64(100);
            let dealer = Dealer::new_with_secret(threshold, secret, &mut OsRng).unwrap();
            let player = Player::new(threshold, kind);
            let min_shares = player.min_shares() as u64;

            // Not enough shares.
            let n = min_shares - 1;
            let xs: Vec<_> = (1..=n).map(PrimeField::from_u64).collect();
            let shares = dealer.make_shares(xs, kind);
            let result = player.recover_secret(&shares);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "not enough shares");

            // Duplicate shares.
            let xs = (1..=n)
                .flat_map(|x| std::iter::repeat(x).take(2))
                .map(PrimeField::from_u64)
                .collect();
            let shares = dealer.make_shares(xs, kind);
            let result = player.recover_secret(&shares);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "not distinct shares");

            // Exact number of shares.
            let n = min_shares;
            let xs = (1..=n).map(PrimeField::from_u64).collect();
            let shares = dealer.make_shares(xs, kind);
            let recovered = player.recover_secret(&shares).unwrap();
            assert_eq!(secret, recovered);

            // Too many shares.
            let n = min_shares + 10;
            let xs = (1..=n).map(PrimeField::from_u64).collect();
            let shares = dealer.make_shares(xs, kind);
            let recovered = player.recover_secret(&shares).unwrap();
            assert_eq!(secret, recovered);
        }
    }

    #[test]
    fn test_kdc() {
        let test_cases = vec![
            HandoffKind::DealingPhase,
            HandoffKind::CommitteeUnchanged,
            HandoffKind::CommitteeChanged,
        ];

        for kind in test_cases.into_iter() {
            // Prepare scheme.
            let threshold = 2;
            let key_id = b"key id";
            let dst = b"encode key share";
            let secret = PrimeField::from_u64(100);
            let hash = Suite::hash_to_group(key_id, dst).unwrap();
            let key = hash * secret;
            let dealer = Dealer::new_with_secret(threshold, secret, &mut OsRng).unwrap();
            let player = Player::new(threshold, kind);
            let min_shares = player.min_shares() as u64;

            // Not enough shares.
            let n = min_shares - 1;
            let xs = (1..=n).map(PrimeField::from_u64).collect();
            let shares = dealer.make_shares(xs, kind);
            let vm = dealer.verification_matrix();
            let shareholders: Vec<Shareholder<_>> = shares
                .into_iter()
                .map(|share| VerifiableSecretShare::new(share, vm.clone()).into())
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
            let shares = dealer.make_shares(xs, kind);
            let vm = dealer.verification_matrix();
            let shareholders: Vec<Shareholder<_>> = shares
                .into_iter()
                .map(|share| VerifiableSecretShare::new(share, vm.clone()).into())
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
            let shares = dealer.make_shares(xs, kind);
            let vm = dealer.verification_matrix();
            let shareholders: Vec<Shareholder<_>> = shares
                .into_iter()
                .map(|share| VerifiableSecretShare::new(share, vm.clone()).into())
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
            let shares = dealer.make_shares(xs, kind);
            let vm = dealer.verification_matrix();
            let shareholders: Vec<Shareholder<_>> = shares
                .into_iter()
                .map(|share| VerifiableSecretShare::new(share, vm.clone()).into())
                .collect();
            let key_shares: Vec<_> = shareholders
                .iter()
                .map(|sh| sh.make_key_share::<Suite>(key_id, dst).unwrap())
                .collect();
            let recovered = player.recover_key(&key_shares).unwrap();
            assert_eq!(key, recovered);
        }
    }
}
