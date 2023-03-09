use honggfuzz::fuzz;

use oasis_core_runtime::storage::mkvs::sync::{Proof, ProofVerifier, RawProofEntry};

fn main() {
    loop {
        fuzz!(|entries: Vec<Option<RawProofEntry>>| {
            let proof = Proof {
                entries,
                ..Default::default()
            };

            let pv = ProofVerifier;
            let _ = pv.verify_proof(proof.untrusted_root, &proof);
        });
    }
}
