use tendermint::{crypto::signature, PublicKey, Signature};

use crate::{common::crypto::hash::Hash, consensus::tendermint::TENDERMINT_CONTEXT};

/// A signature verifier that uses the Oasis Core domain separation scheme.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DomSepVerifier;

impl signature::Verifier for DomSepVerifier {
    fn verify(
        pubkey: PublicKey,
        msg: &[u8],
        signature: &Signature,
    ) -> Result<(), signature::Error> {
        // Use Oasis Core domain separation scheme.
        let msg = Hash::digest_bytes_list(&[TENDERMINT_CONTEXT, msg]);

        // Forward the actual verification to the Tendermint's default verifier.
        tendermint::crypto::default::signature::Verifier::verify(pubkey, msg.as_ref(), signature)
    }
}
