//! Merkle proofs used in Tendermint networks
//!
//! Rewritten to Rust from:
//! https://github.com/tendermint/tendermint/blob/main/crypto/merkle/proof.go
//!
//! Helper functions copied from:
//! https://github.com/informalsystems/tendermint-rs/blob/main/tendermint/src/merkle.rs

use std::cmp::Ordering;

use anyhow::{anyhow, Result};
use rustc_hex::ToHex;
use sha2::{Digest, Sha256};

use tendermint::merkle::{Hash, HASH_SIZE};

/// Maximum number of aunts that can be included in a Proof.
/// This corresponds to a tree of size 2^100, which should be sufficient for all conceivable purposes.
/// This maximum helps prevent Denial-of-Service attacks by limiting the size of the proofs.
pub const MAX_AUNTS: usize = 100;

/// Proof represents a Merkle proof.
///
/// NOTE: The convention for proofs is to include leaf hashes but to
/// exclude the root hash.
/// This convention is implemented across IAVL range proofs as well.
/// Keep this consistent unless there's a very good reason to change
/// everything.  This also affects the generalized proof system as
/// well.
#[derive(Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Proof {
    pub total: i64,       // Total number of items.
    pub index: i64,       // Index of item to prove.
    pub leaf_hash: Hash,  // Hash of item value.
    pub aunts: Vec<Hash>, // Hashes from leaf's sibling to a root's child.
}

impl Proof {
    /// Verify that the Proof proves the root hash.
    /// Check index/total manually if needed.
    pub fn verify(&self, root_hash: Hash, leaf: Hash) -> Result<()> {
        if self.total < 0 {
            return Err(anyhow!("proof total must be positive"));
        }
        if self.index < 0 {
            return Err(anyhow!("proof index cannot be negative"));
        }
        if self.aunts.len() > MAX_AUNTS {
            return Err(anyhow!(
                "expected no more than {} aunts, got {}",
                MAX_AUNTS,
                self.aunts.len()
            ));
        }

        let leaf_hash = leaf_hash(&leaf);
        match self.leaf_hash.cmp(&leaf_hash) {
            Ordering::Equal => (),
            _ => {
                return Err(anyhow!(
                    "invalid leaf hash: wanted {} got {}",
                    leaf_hash.to_hex::<String>(),
                    self.leaf_hash.to_hex::<String>(),
                ));
            }
        }

        let computed_hash = self.compute_root_hash().ok_or_else(|| {
            anyhow!(
                "invalid root hash: wanted {} got None",
                root_hash.to_hex::<String>()
            )
        })?;
        match computed_hash.cmp(&root_hash) {
            Ordering::Equal => (),
            _ => {
                return Err(anyhow!(
                    "invalid root hash: wanted {} got {}",
                    root_hash.to_hex::<String>(),
                    computed_hash.to_hex::<String>(),
                ));
            }
        }

        Ok(())
    }

    /// Compute the root hash given a leaf hash. Does not verify the result.
    pub fn compute_root_hash(&self) -> Option<Hash> {
        Self::compute_hash_from_aunts(self.index, self.total, self.leaf_hash, &self.aunts)
    }

    /// Use the leaf_hash and inner_hashes to get the root merkle hash.
    /// If the length of the inner_hashes slice isn't exactly correct, the result is None.
    /// Recursive impl.
    fn compute_hash_from_aunts(
        index: i64,
        total: i64,
        leaf_hash: Hash,
        inner_hashes: &[Hash],
    ) -> Option<Hash> {
        if index >= total || index < 0 || total <= 0 {
            return None;
        }
        match total {
            0 => unreachable!("cannot call compute_hash_from_aunts() with 0 total"), // Handled above.
            1 => {
                if !inner_hashes.is_empty() {
                    return None;
                }
                Some(leaf_hash)
            }
            _ => {
                if inner_hashes.is_empty() {
                    return None;
                }
                let last_idx = inner_hashes.len() - 1;
                let last_hash = inner_hashes[last_idx];
                let inner_hashes = &inner_hashes[..last_idx];

                let num_left = get_split_point(total as usize) as i64;
                if index < num_left {
                    if let Some(left_hash) =
                        Self::compute_hash_from_aunts(index, num_left, leaf_hash, inner_hashes)
                    {
                        return Some(inner_hash(&left_hash, &last_hash));
                    }
                    return None;
                }
                if let Some(right_hash) = Self::compute_hash_from_aunts(
                    index - num_left,
                    total - num_left,
                    leaf_hash,
                    inner_hashes,
                ) {
                    return Some(inner_hash(&last_hash, &right_hash));
                }
                None
            }
        }
    }
}

/// returns the largest power of 2 less than length
fn get_split_point(length: usize) -> usize {
    match length {
        0 => panic!("tree is empty!"),
        1 => panic!("tree has only one element!"),
        2 => 1,
        _ => length.next_power_of_two() / 2,
    }
}

/// tmhash(0x00 || leaf)
fn leaf_hash(bytes: &[u8]) -> Hash {
    // make a new array starting with 0 and copy in the bytes
    let mut leaf_bytes = Vec::with_capacity(bytes.len() + 1);
    leaf_bytes.push(0x00);
    leaf_bytes.extend_from_slice(bytes);

    // hash it !
    let digest = Sha256::digest(&leaf_bytes);

    // copy the GenericArray out
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(&digest);
    hash_bytes
}

/// tmhash(0x01 || left || right)
fn inner_hash(left: &[u8], right: &[u8]) -> Hash {
    // make a new array starting with 0x1 and copy in the bytes
    let mut inner_bytes = Vec::with_capacity(left.len() + right.len() + 1);
    inner_bytes.push(0x01);
    inner_bytes.extend_from_slice(left);
    inner_bytes.extend_from_slice(right);

    // hash it !
    let digest = Sha256::digest(&inner_bytes);

    // copy the GenericArray out
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(&digest);
    hash_bytes
}
