use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use anyhow::{anyhow, Result};
use arbitrary::Arbitrary;

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

struct ProofNode {
    serialized: Vec<u8>,
    children: Vec<Hash>,
}

/// A Merkle proof builder.
pub struct ProofBuilder {
    root: Hash,
    included: BTreeMap<Hash, ProofNode>,
}

impl ProofBuilder {
    /// Create a new proof builder for the given root hash.
    pub fn new(root: Hash) -> Self {
        Self {
            root,
            included: BTreeMap::new(),
        }
    }

    /// Add a node to the set of included nodes.
    ///
    /// # Panics
    ///
    /// Panics if the node is not clean.
    pub fn include(&mut self, node: &NodeBox) {
        if !node.is_clean() {
            panic!("proof builder: node is not clean");
        }

        // If node is already included, skip.
        let nh = node.get_hash();
        if self.included.contains_key(&nh) {
            return;
        }
        let mut pn = ProofNode {
            serialized: node
                .compact_marshal_binary()
                .expect("marshaling node in proof"),
            children: vec![],
        };

        // For internal nodes, also include children.
        if let NodeBox::Internal(nd) = node {
            let ch = nd
                .left
                .borrow()
                .node
                .as_ref()
                .map(|n| n.borrow().get_hash())
                .unwrap_or(Hash::empty_hash());
            pn.children.push(ch);

            let ch = nd
                .right
                .borrow()
                .node
                .as_ref()
                .map(|n| n.borrow().get_hash())
                .unwrap_or(Hash::empty_hash());
            pn.children.push(ch);
        }

        self.included.insert(nh, pn);
    }

    /// Build the (unverified) proof.
    pub fn build(&self) -> Proof {
        let mut proof = Proof {
            untrusted_root: self.root,
            entries: vec![],
        };
        self._build(&mut proof, &self.root);

        proof
    }

    fn _build(&self, p: &mut Proof, h: &Hash) {
        if h.is_empty() {
            // Append nil for empty nodes.
            p.entries.push(None);
            return;
        }

        match self.included.get(h) {
            None => {
                // Node is not included in this proof, just add hash of subtree.
                let mut data = Vec::with_capacity(h.as_ref().len() + 1);
                data.push(PROOF_ENTRY_HASH);
                data.extend_from_slice(h.as_ref());

                p.entries.push(Some(RawProofEntry(data)));
            }
            Some(pn) => {
                // Pre-order traversal, add visited node.
                let mut data = Vec::with_capacity(pn.serialized.len() + 1);
                data.push(PROOF_ENTRY_FULL);
                data.extend_from_slice(&pn.serialized);

                p.entries.push(Some(RawProofEntry(data)));

                // Recurse into children.
                for ch in pn.children.iter() {
                    self._build(p, ch);
                }
            }
        }
    }
}

/// A proof verifier enables verifying proofs returned by the ReadSyncer API.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a proof and generate an in-memory subtree representing the
    /// nodes which are included in the proof.
    pub fn verify_proof(&self, root: Hash, proof: &Proof) -> Result<NodePtrRef> {
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

        let (idx, root_node) = Self::_verify_proof(proof, 0)?;
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

    fn _verify_proof(proof: &Proof, idx: usize) -> Result<(usize, NodePtrRef)> {
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
                    let result = Self::_verify_proof(proof, pos)?;
                    pos = result.0;
                    nd.left = result.1;
                    // Right.
                    let result = Self::_verify_proof(proof, pos)?;
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
    use rustc_hex::ToHex;

    use crate::storage::mkvs::{cache::Cache, sync::NoopReadSyncer};

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
        pv.verify_proof(root_hash, &proof)
            .expect("verify proof should not fail with a valid proof");

        // Invalid proofs should not verify.

        // Empty proof.
        let empty_proof = Proof::default();
        let result = pv.verify_proof(root_hash, &empty_proof);
        assert!(
            result.is_err(),
            "verify proof should fail with an empty proof"
        );

        // Different root.
        let bogus_hash = Hash::digest_bytes(b"i am a bogus hash");
        let result = pv.verify_proof(bogus_hash, &proof);
        assert!(
            result.is_err(),
            "verify proof should fail with a proof for a different root"
        );

        // Different hash element.
        let mut corrupted = proof.clone();
        corrupted.entries[4].as_mut().unwrap()[10] = 0x00;
        let result = pv.verify_proof(root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Corrupted full node.
        let mut corrupted = proof.clone();
        corrupted.entries[0].as_mut().unwrap().truncate(3);
        let result = pv.verify_proof(root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Corrupted hash.
        let mut corrupted = proof.clone();
        corrupted.entries[2].as_mut().unwrap().truncate(3);
        let result = pv.verify_proof(root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Corrupted proof element type.
        let mut corrupted = proof.clone();
        corrupted.entries[3].as_mut().unwrap()[0] = 0xaa;
        let result = pv.verify_proof(root_hash, &corrupted);
        assert!(
            result.is_err(),
            "verify proof should fail with invalid proof"
        );

        // Missing elements.
        let mut corrupted = proof.clone();
        corrupted.entries.truncate(3);
        let result = pv.verify_proof(root_hash, &corrupted);
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
        pv.verify_proof(root_hash, &proof)
            .expect("verify proof should not fail with a valid proof");

        // Duplicate some nodes and add them to the end.
        proof.entries.push(proof.entries[0].clone());

        pv.verify_proof(root_hash, &proof)
            .expect_err("proof with extra data should fail to validate");
    }

    #[test]
    fn test_proof_builder() {
        // NOTE: Ensure this test matches TestProof in go/storage/mkvs/syncer_test.go.

        // Prepare test tree.
        let mut tree = Tree::builder()
            .with_root(Root {
                hash: Hash::empty_hash(),
                ..Default::default()
            })
            .build(Box::new(NoopReadSyncer));
        for i in 0..10 {
            let k = format!("key {}", i).into_bytes();
            let v = format!("value {}", i).into_bytes();
            tree.insert(&k, &v).expect("insert");
        }
        let roothash = tree.commit(Default::default(), 1).expect("commit");

        // Ensure tree matches Go side.
        assert_eq!(
            roothash.0.to_hex::<String>(),
            "59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613",
        );

        // Ensure proof matches Go side.
        let mut pb = ProofBuilder::new(roothash);
        let root_only_proof = pb.build();
        assert_eq!(
            base64::encode(cbor::to_vec(root_only_proof)),
            "omdlbnRyaWVzgVghAlnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYTbnVudHJ1c3RlZF9yb290WCBZ5nwv3Ai44Q3Qi7a47+YU/Mll7LiWJfl/F/h/BxBGEw==",
        );

        // Include root node.
        let root_ptr = tree.cache.borrow().get_pending_root();
        let root_node = root_ptr.borrow().get_node();
        pb.include(&*root_node.borrow());
        // Include root.left node.
        pb.include(
            &*noderef_as!(root_node, Internal)
                .left
                .borrow()
                .get_node()
                .borrow(),
        );
        // Ensure proofs matches Go side.
        let test_proof = pb.build();
        assert_eq!(
            base64::encode(cbor::to_vec(test_proof)),
		    "omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=",
        );
    }

    #[test]
    fn test_tree_proofs() {
        // NOTE: Ensure this test matches TestTreeProofs in go/storage/mkvs/syncer_test.go.

        // Prepare test tree.
        let mut tree = Tree::builder()
            .with_root(Root {
                hash: Hash::empty_hash(),
                ..Default::default()
            })
            .build(Box::new(NoopReadSyncer));
        let mut keys = vec![];
        for i in 0..10 {
            let k = format!("key {}", i).into_bytes();
            let v = format!("value {}", i).into_bytes();
            tree.insert(&k, &v).expect("insert");
            keys.push(k);
        }
        let roothash = tree.commit(Default::default(), 1).expect("commit");

        // Ensure tree matches Go side.
        assert_eq!(
            roothash.0.to_hex::<String>(),
            "59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613",
        );

        // Ensure tree proofs match Go side.
        // Keys[0].
        let proof = tree
            .get_proof(&keys[0])
            .expect("get proof keys[0] works")
            .expect("proof keys[0] exists");
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
		    "omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJGAQEBAAACVAEABQBrZXkgMAcAAAB2YWx1ZSAwWCECV0zNDCAeH8Ryb6sX6LfUCc6AVgGKkECVzHlN/mXjJb5YIQIOdiNCGwCnl8P6B/RblhgVjoKcZRGsQRO0m8mn6KMfjFghAqbCZ5IzpyIHOPsn76bKgnCGB4eXpXdYTTFk0+2qwHxxWCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIFnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYT",
        );

        // Keys[5].
        let proof = tree
            .get_proof(&keys[5])
            .expect("get proof keys[5] works")
            .expect("proof keys[5] exists");
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
		    "omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlRgEBAQCAAkYBAQEAAAJYIQLGCmUSnaMGinOcyqgElnV7MITsg7YFvkKovKkL4iISGlQBAAUAa2V5IDUHAAAAdmFsdWUgNVghArfWCo9vCnfczvIpvZVKjt4HyniNlmZgacnueN4UEYe1WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIFnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYT",
        );

        // Keys[9].
        let proof = tree
            .get_proof(&keys[9])
            .expect("get proof keys[9] works")
            .expect("proof keys[9] exists");
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
		    "omdlbnRyaWVzhUoBASQAa2V5IDACWCECJueKTLbwFMAiJitvfP3+tOruv3XChOjYSpH3U9/Xo/1GAQEDAIACWCECMMFu3slwotsl8hQsxQ/VPkrMtYMEsIrJAUH5PvSglANUAQAFAGtleSA5BwAAAHZhbHVlIDludW50cnVzdGVkX3Jvb3RYIFnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYT",
        );
    }
}
