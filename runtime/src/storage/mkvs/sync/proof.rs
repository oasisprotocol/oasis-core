use std::{
    cell::RefCell,
    collections::BTreeMap,
    ops::{Deref, DerefMut},
    rc::Rc,
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

// Min and max supported proof versions.
const MIN_PROOF_VERSION: u16 = 0;
const MAX_PROOF_VERSION: u16 = 1;

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
    // The proof version.
    //
    // We don't use `Versioned` since we want version 0 proofs to be
    // backwards compatible with the old structure which was not versioned.
    //
    // Version 0:
    // Initial format.
    //
    // Version 1 change:
    // Leaf nodes are included separately, as children. In version 0 the leaf node was
    // serialized within the internal node.  The rationale behind this change is to eliminate
    // the need to serialize all leaf nodes on the path when proving the existence of a
    // specific value.
    #[cbor(optional)]
    pub v: u16,
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
    proof_version: u16,
    root: Hash,
    included: BTreeMap<Hash, ProofNode>,
}

impl ProofBuilder {
    /// Create a new proof builder for the given root hash.
    pub fn new(root: Hash) -> Self {
        Self::new_with_version(root, MAX_PROOF_VERSION).unwrap()
    }

    /// Create a new proof builder for the given root hash and proof version.
    pub fn new_with_version(root: Hash, proof_version: u16) -> Result<Self> {
        if !(MIN_PROOF_VERSION..=MAX_PROOF_VERSION).contains(&proof_version) {
            return Err(anyhow!(
                "proof builder: unsupported proof version: {}",
                proof_version
            ));
        }

        Ok(Self {
            proof_version,
            root,
            included: BTreeMap::new(),
        })
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
                .compact_marshal_binary(self.proof_version)
                .expect("marshaling node in proof"),
            children: vec![],
        };

        // For internal nodes, also include children.
        if let NodeBox::Internal(nd) = node {
            fn get_child_hash(nd: &Rc<RefCell<NodePointer>>) -> Hash {
                nd.borrow()
                    .node
                    .as_ref()
                    .map(|n| n.borrow().get_hash())
                    .unwrap_or_else(Hash::empty_hash)
            }

            if self.proof_version == 1 {
                // In proof version 1, leaf nodes are included separately as children.
                pn.children.push(get_child_hash(&nd.leaf_node));
            }
            pn.children.push(get_child_hash(&nd.left));
            pn.children.push(get_child_hash(&nd.right));
        }

        self.included.insert(nh, pn);
    }

    /// Build the (unverified) proof.
    pub fn build(&self) -> Proof {
        let mut proof = Proof {
            v: self.proof_version,
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
        // Check proof version.
        if !(MIN_PROOF_VERSION..=MAX_PROOF_VERSION).contains(&proof.v) {
            return Err(anyhow!("verifier: unsupported proof version: {}", proof.v));
        }

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
                    match proof.v {
                        0 => {
                            // In proof version 0, leaf nodes are included within the internal node.
                        }
                        1 => {
                            // In proof version 1, leaf nodes are included separately as children.
                            (pos, nd.leaf_node) = Self::_verify_proof(proof, pos)?;
                        }
                        _ => {
                            // Should not happen, checked in verify_proof.
                            panic!("unsupported proof version: {:?}", proof.v)
                        }
                    }

                    // Left.
                    (pos, nd.left) = Self::_verify_proof(proof, pos)?;
                    // Right.
                    (pos, nd.right) = Self::_verify_proof(proof, pos)?;

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
    use rustc_hex::ToHex;

    use crate::storage::mkvs::{cache::Cache, sync::NoopReadSyncer};

    use super::*;

    #[test]
    fn test_proof() {
        // Test vectors generated by Go.

        // V0 proof.
        let test_vector_proof = base64::decode(
            "omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+\
yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2\
uO/mFPzJZey4liX5fxf4fwcQRhM=",
        ).unwrap();

        let test_vector_root_hash =
            "59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613";

        // Proof should decode.
        let proof: Proof =
            cbor::from_slice(&test_vector_proof).expect("V0 proof should deserialize");
        assert_eq!(proof.v, 0, "proof version should be 0");
        let root_hash = Hash::from(test_vector_root_hash);

        // Proof should round-trip.
        assert_eq!(
            test_vector_proof,
            cbor::to_vec(proof.clone()),
            "proof should round-trip"
        );

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

        // V1 proof.
        let test_vector_proof = base64::decode(
            "o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9kYBAQEAAAL2WCECwWW1hGEPh0DAc506YSKBjWvTakkfoieGKJsqWH2d5iVYIQKmwmeSM6ciBzj7J+\
            +myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCBZ5nwv3Ai44Q3Qi7a47+\
            YU/Mll7LiWJfl/F/h/BxBGEw=="
        ).unwrap();

        // Proof should decode.
        let proof: Proof =
            cbor::from_slice(&test_vector_proof).expect("V1 proof should deserialize");
        assert_eq!(proof.v, 1, "proof version should be 1");
        let root_hash = Hash::from(test_vector_root_hash);

        // Proof should round-trip.
        assert_eq!(
            test_vector_proof,
            cbor::to_vec(proof.clone()),
            "proof should round-trip"
        );

        // Proof should verify.
        let pv = ProofVerifier;
        pv.verify_proof(root_hash, &proof)
            .expect("verify proof should not fail with a valid proof");
    }

    #[test]
    fn test_proof_builder_v1() {
        // NOTE: Ensure this test matches TestProofV1 in go/storage/mkvs/syncer_test.go.

        // Prepare test tree.
        let mut tree = Tree::builder()
            .with_root(Root {
                hash: Hash::empty_hash(),
                ..Default::default()
            })
            .build(Box::new(NoopReadSyncer));
        for i in 0..11 {
            let k = format!("key {}", i).into_bytes();
            let v = format!("value {}", i).into_bytes();
            tree.insert(&k, &v).expect("insert");
        }
        let roothash = tree.commit(Default::default(), 1).expect("commit");

        let mut pb = ProofBuilder::new(roothash);

        // Ensure proof matches Go side.
        let proof = pb.build();
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
            "o2F2AWdlbnRyaWVzgVghAqlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpFbnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ=="
        );

        // Include root node.
        let root_ptr = tree.cache.borrow().get_pending_root();
        let root_node = root_ptr.borrow().get_node();
        pb.include(&*root_node.borrow());
        // Ensure proof matches Go side.
        let proof = pb.build();
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
		    "o2F2AWdlbnRyaWVzhEoBASQAa2V5IDAC9lghAhQ6RgqFtADx+B6VKE0CVRrfDHmwgZwU3ewsj4gswWv+WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
        );

        // Include root.left node.
        let root_left = noderef_as!(root_node, Internal).left.borrow().get_node();
        pb.include(&*root_left.borrow());
        // Ensure proof matches Go side.
        let proof = pb.build();
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
            "o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
        );

        // Include root.left.left node.
        let root_left2 = noderef_as!(root_left, Internal).left.borrow().get_node();
        pb.include(&*root_left2.borrow());

        // Include root.left.left.left node.
        let root_left3: Rc<RefCell<NodeBox>> =
            noderef_as!(root_left2, Internal).left.borrow().get_node();
        pb.include(&*root_left3.borrow());

        // Include root.left.left.left.right node.
        let root_left3_right = noderef_as!(root_left3, Internal).right.borrow().get_node();
        pb.include(&*root_left3_right.borrow());

        // Include root.left.left.left.right.left leaf node.
        let bottom = noderef_as!(root_left3_right, Internal)
            .left
            .borrow()
            .get_node();
        pb.include(&*bottom.borrow());
        // Ensure proof matches Go side.
        let proof = pb.build();
        assert_eq!(
            base64::encode(cbor::to_vec(proof)),
		    "o2F2AWdlbnRyaWVzkEoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lghAlF8/rp9QOAd1qSchhUxDtVkpmnze6sjz5IfFhdOuaypRgEBAQCAAlghAldMzQwgHh/Ecm+rF+i31AnOgFYBipBAlcx5Tf5l4yW+VgEABgBrZXkgMTAIAAAAdmFsdWUgMTD2WCECDnYjQhsAp5fD+gf0W5YYFY6CnGURrEETtJvJp+ijH4xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
        );
    }

    #[test]
    fn test_proof_extra_nodes() {
        // V0 proof.
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

        // V1 proof.
        let test_vector_proof = base64::decode(
                "o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9kYBAQEAAAL2WCECwWW1hGEPh0DAc506YSKBjWvTakkfoieGKJsqWH2d5iVYIQKmwmeSM6ciBzj7J+\
                +myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCBZ5nwv3Ai44Q3Qi7a47+\
                YU/Mll7LiWJfl/F/h/BxBGEw=="
            ).unwrap();

        // Proof should decode.
        let mut proof: Proof =
            cbor::from_slice(&test_vector_proof).expect("V1 proof should deserialize");
        assert_eq!(proof.v, 1, "proof version should be 1");
        let root_hash = Hash::from(test_vector_root_hash);

        // Proof should verify.
        let pv = ProofVerifier;
        pv.verify_proof(root_hash, &proof)
            .expect("verify proof should not fail with a valid proof");

        // Duplicate some nodes and add them to the end.
        proof.entries.push(proof.entries[0].clone());
        pv.verify_proof(root_hash, &proof)
            .expect_err("verify proof should fail with an invalid proof");
    }

    #[test]
    fn test_proof_builder_v0() {
        // NOTE: Ensure this test matches TestProofV0 in go/storage/mkvs/syncer_test.go.

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
        let mut pb = ProofBuilder::new_with_version(roothash, 0).expect("new proof builder v0");
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
        for i in 0..11 {
            let k = format!("key {}", i).into_bytes();
            let v = format!("value {}", i).into_bytes();
            tree.insert(&k, &v).expect("insert");
            keys.push(k);
        }
        let roothash = tree.commit(Default::default(), 1).expect("commit");
        // Ensure tree matches Go side.
        assert_eq!(
            roothash.0.to_hex::<String>(),
            "a940b9ded7621a2b10497c846f46dc7778397979551d71bee2c07a9319e6aa45",
        );

        for tc in vec![
            // Note: Tree::get_proof doesn't support version 0 proofs.
            // We test only version 1 proofs here.
            (
                // Proof v.
                1,
                vec![
                    // 0.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lQBAAUAa2V5IDAHAAAAdmFsdWUgMFghAlO8PtYkGTEg304b/z/cv4oH6+BRaJ88layf7VgIl3xTWCECDnYjQhsAp5fD+gf0W5YYFY6CnGURrEETtJvJp+ijH4xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 1.
                    "o2F2AWdlbnRyaWVzkEoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lghAlF8/rp9QOAd1qSchhUxDtVkpmnze6sjz5IfFhdOuaypRgEBAQCAAlQBAAUAa2V5IDEHAAAAdmFsdWUgMVghAm2EG0dH85+yEl5rdT67+D59/gbjHB9qDtnCcv0kkuje9lghAg52I0IbAKeXw/oH9FuWGBWOgpxlEaxBE7Sbyafoox+MWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
                    // 2.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZYIQLnu/nMm00WQo9ZxRbRFM/hVtoTov4Phs3vIQ/6jS/29kYBAQEAgAL2VAEABQBrZXkgMgcAAAB2YWx1ZSAyWCECJtIdvBvSs2Vh4Z1ghY3zvHvK8JsoBmt3+dBpRCNdA/xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 3.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZYIQLnu/nMm00WQo9ZxRbRFM/hVtoTov4Phs3vIQ/6jS/29kYBAQEAgAL2WCECoYj1TutUHeB1K0anT1hRts8AKOw8AfEtn963XMVxV1xUAQAFAGtleSAzBwAAAHZhbHVlIDNYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 4.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9kYBAQEAAAL2VAEABQBrZXkgNAcAAAB2YWx1ZSA0WCEC7uES0HThvwiREsS6OKGDOodNGn7WGC3BTBJSLBIsJf1YIQK31gqPbwp33M7yKb2VSo7eB8p4jZZmYGnJ7njeFBGHtVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 5.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9kYBAQEAAAL2WCECxgplEp2jBopznMqoBJZ1ezCE7IO2Bb5CqLypC+IiEhpUAQAFAGtleSA1BwAAAHZhbHVlIDVYIQK31gqPbwp33M7yKb2VSo7eB8p4jZZmYGnJ7njeFBGHtVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 6.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9lghAivLwJbWkwZ8nROaPHGxpfthiG8vqyPbvzhkEEX793dIRgEBAQCAAvZUAQAFAGtleSA2BwAAAHZhbHVlIDZYIQK96CvAaM4vOReqLe+AoO6KajYFZiUsAyvSi8rEgClU7FghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 7.
                    "o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9lghAivLwJbWkwZ8nROaPHGxpfthiG8vqyPbvzhkEEX793dIRgEBAQCAAvZYIQICPF9slSfLMzCKpIGUKFWpXWq5dxfVdfe6wfGW6xjer1QBAAUAa2V5IDcHAAAAdmFsdWUgN1ghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                    // 8.
                    "o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9lghAhQ6RgqFtADx+B6VKE0CVRrfDHmwgZwU3ewsj4gswWv+RgEBAwCAAvZUAQAFAGtleSA4BwAAAHZhbHVlIDhYIQINczJ806eMr+T/iGsJmo8/JQFXZtjy1/k+as0V9FdfVG51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
                    // 9.
                    "o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9lghAhQ6RgqFtADx+B6VKE0CVRrfDHmwgZwU3ewsj4gswWv+RgEBAwCAAvZYIQIwwW7eyXCi2yXyFCzFD9U+Ssy1gwSwiskBQfk+9KCUA1QBAAUAa2V5IDkHAAAAdmFsdWUgOW51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
                    // 10.
                    "o2F2AWdlbnRyaWVzkEoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lghAlF8/rp9QOAd1qSchhUxDtVkpmnze6sjz5IfFhdOuaypRgEBAQCAAlghAldMzQwgHh/Ecm+rF+i31AnOgFYBipBAlcx5Tf5l4yW+VgEABgBrZXkgMTAIAAAAdmFsdWUgMTD2WCECDnYjQhsAp5fD+gf0W5YYFY6CnGURrEETtJvJp+ijH4xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
                ],
            ),
            ]{
                // Ensure tree proofs match Go side.
                for (i, k) in tc.1.iter().enumerate() {
                    let proof = tree.get_proof(&keys[i]).expect("get proof works").expect("proof exists");
                    assert_eq!(
                        base64::encode(cbor::to_vec(proof.clone())),
                        *k,
                        "expected proof for keys[{}]",
                        i
                    );
                    // Proof should verify.
                    let pv = ProofVerifier;
                    pv.verify_proof(roothash, &proof)
                        .expect("verify proof should not fail with a valid proof");
                }
            };
    }
}
