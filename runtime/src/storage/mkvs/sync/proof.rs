use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, Result};
use arbitrary::Arbitrary;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    storage::mkvs::{marshal::Marshal, tree::*},
};

/// Proof entry type for full nodes.
const PROOF_ENTRY_FULL: u8 = 0x01;
/// Proof entry type for subtree hashes.
const PROOF_ENTRY_HASH: u8 = 0x02;

/// A raw proof entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode, Arbitrary)]
#[cbor(transparent)]
pub struct RawProofEntry(pub Vec<u8>);

impl AsRef<[u8]> for RawProofEntry {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for RawProofEntry {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RawProofEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<RawProofEntry> for Vec<u8> {
    fn from(val: RawProofEntry) -> Self {
        val.0
    }
}

impl From<Vec<u8>> for RawProofEntry {
    fn from(v: Vec<u8>) -> RawProofEntry {
        RawProofEntry(v)
    }
}

/// A Merkle proof for a subtree.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct Proof {
    /// The root hash this proof is for. This should only be used as a quick
    /// sanity check and proof verification MUST use an independently obtained
    /// root hash as the prover can provide any root.
    pub untrusted_root: Hash,
    /// Proof entries in pre-order traversal.
    pub entries: Vec<Option<RawProofEntry>>,
}

/// A proof verifier enables verifying proofs returned by the ReadSyncer API.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a proof and generate an in-memory subtree representing the
    /// nodes which are included in the proof.
    pub fn verify_proof(&self, _ctx: Context, root: Hash, proof: &Proof) -> Result<NodePtrRef> {
        // Sanity check that the proof is for the correct root (as otherwise it
        // makes no sense to verify the proof).
        if proof.untrusted_root != root {
            return Err(anyhow!(
                "verifier: got proof for unexpected root (expected: {:?} got {:?})",
                root,
                proof.untrusted_root,
            ));
        }
        if proof.entries.is_empty() {
            return Err(anyhow!("verifier: empty proof"));
        }

        let (idx, root_node) = self._verify_proof(proof, 0)?;
        // Make sure that all of the entries in the proof have been used. The returned index should
        // point to just beyond the last element.
        if idx != proof.entries.len() {
            return Err(anyhow!("verifier: unused entries in proof"));
        }
        let root_hash = root_node.borrow().hash;
        if root_hash != root {
            return Err(anyhow!(
                "verifier: bad root (expected: {:?} got {:?})",
                root,
                root_hash,
            ));
        }

        Ok(root_node)
    }

    fn _verify_proof(&self, proof: &Proof, idx: usize) -> Result<(usize, NodePtrRef)> {
        if idx >= proof.entries.len() {
            return Err(anyhow!("verifier: malformed proof"));
        }
        let entry = match &proof.entries[idx] {
            Some(entry) => entry.as_ref(),
            None => return Ok((idx + 1, NodePointer::null_ptr())),
        };
        if entry.is_empty() {
            return Err(anyhow!("verifier: malformed proof"));
        }

        match entry[0] {
            PROOF_ENTRY_FULL => {
                // Full node.
                let mut node = NodeBox::default();
                node.unmarshal_binary(&entry[1..])?;

                // For internal nodes, also decode children.
                let mut pos = idx + 1;
                if let NodeBox::Internal(ref mut nd) = node {
                    // Left.
                    let result = self._verify_proof(proof, pos)?;
                    pos = result.0;
                    nd.left = result.1;
                    // Right.
                    let result = self._verify_proof(proof, pos)?;
                    pos = result.0;
                    nd.right = result.1;

                    // Recompute hash as hashes were not recomputed for compact encoding.
                    nd.update_hash();
                }

                Ok((pos, NodePointer::from_node(node)))
            }
            PROOF_ENTRY_HASH => {
                // Hash of a node.
                let entry = &entry[1..];
                if entry.len() != Hash::len() {
                    return Err(anyhow!("verifier: malformed hash entry"));
                }

                Ok((idx + 1, NodePointer::hash_ptr(entry.into())))
            }
            entry_type => Err(anyhow!(
                "verifier: unexpected entry in proof ({:?})",
                entry_type
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use base64;
    use io_context::Context;

    use super::*;

    #[test]
    fn test_proof() {
        // Test vector generated by Go.
        // TODO: Provide multiple test vectors.
        let test_vector_proof = base64::decode(
            "omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+\
yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2\
uO/mFPzJZey4liX5fxf4fwcQRhM=",
        ).unwrap();
        let test_vector_root_hash =
            "59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613";

        // Proof should decode.
        let proof: Proof = cbor::from_slice(&test_vector_proof).expect("proof should deserialize");
        let root_hash = Hash::from(test_vector_root_hash);

        // Proof should verify.
        let pv = ProofVerifier;
        pv.verify_proof(Context::background(), root_hash, &proof)
            .expect("verify proof should not fail with a valid proof");

        // Invalid proofs should not verify.

        // Empty proof.
        let empty_proof = Proof::default();
        let result = pv.verify_proof(Context::background(), root_hash, &empty_proof);
        assert!(
            result.is_err(),
            "verify proof should fail with an empty proof"
        );

        // Different root.
        let bogus_hash = Hash::digest_bytes(b"i am a bogus hash");
        let result = pv.verify_proof(Context::background(), bogus_hash, &proof);
        assert!(
            result.is_err(),
            "verify proof should fail with a proof for a different root"
        );

        // Different hash element.
        let mut corrupted = proof.clone();
        corrupted.entries[4].as_mut().unwrap()[10] = 0x00;
        let result = pv.verify_proof(Context::background(), root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Corrupted full node.
        let mut corrupted = proof.clone();
        corrupted.entries[0].as_mut().unwrap().truncate(3);
        let result = pv.verify_proof(Context::background(), root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Corrupted hash.
        let mut corrupted = proof.clone();
        corrupted.entries[2].as_mut().unwrap().truncate(3);
        let result = pv.verify_proof(Context::background(), root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Corrupted proof element type.
        let mut corrupted = proof.clone();
        corrupted.entries[3].as_mut().unwrap()[0] = 0xaa;
        let result = pv.verify_proof(Context::background(), root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Missing elements.
        let mut corrupted = proof.clone();
        corrupted.entries.truncate(3);
        let result = pv.verify_proof(Context::background(), root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );
    }

    #[test]
    fn test_proof_extra_nodes() {
        let test_vector_proof = base64::decode(
            "omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+\
yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2\
uO/mFPzJZey4liX5fxf4fwcQRhM=",
        ).unwrap();
        let test_vector_root_hash =
            "59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613";

        // Proof should decode.
        let mut proof: Proof =
            cbor::from_slice(&test_vector_proof).expect("proof should deserialize");
        let root_hash = Hash::from(test_vector_root_hash);

        // Proof should verify.
        let pv = ProofVerifier;
        pv.verify_proof(Context::background(), root_hash, &proof)
            .expect("verify proof should not fail with a valid proof");

        // Duplicate some nodes and add them to the end.
        proof.entries.push(proof.entries[0].clone());

        pv.verify_proof(Context::background(), root_hash, &proof)
            .expect_err("proof with extra data should fail to validate");
    }
}
