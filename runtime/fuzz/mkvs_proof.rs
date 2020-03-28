use honggfuzz::fuzz;
use io_context::Context;

use oasis_core_runtime::storage::mkvs::sync::{Proof, ProofVerifier, RawProofEntry};

fn main() {
    loop {
        fuzz!(|entries: Vec<Option<RawProofEntry>>| {
            let proof = Proof {
                entries,
                ..Default::default()
            };

            let pv = ProofVerifier;
            let _ = pv.verify_proof(Context::background(), proof.untrusted_root, &proof);
        });
    }
}
