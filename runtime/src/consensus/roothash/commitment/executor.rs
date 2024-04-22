use std::any::Any;

use anyhow::{anyhow, Result};

use crate::{
    common::{
        crypto::{
            hash::Hash,
            signature::{
                signature_context_with_chain_separation, signature_context_with_runtime_separation,
                PublicKey, Signature, Signer,
            },
        },
        namespace::Namespace,
    },
    consensus::roothash::{Header, Message},
};

use super::OpenCommitment;

/// The signature context used to sign compute results headers with RAK.
pub const COMPUTE_RESULTS_HEADER_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/roothash: compute results header";

/// The signature context used to sign executor worker commitments.
pub const EXECUTOR_COMMITMENT_SIGNATURE_CONTEXT: &[u8] =
    b"oasis-core/roothash: executor commitment";

fn executor_commitment_signature_context(
    runtime_id: &Namespace,
    chain_context: &String,
) -> Vec<u8> {
    let context = EXECUTOR_COMMITMENT_SIGNATURE_CONTEXT.to_vec();
    let context = signature_context_with_runtime_separation(context, runtime_id);
    signature_context_with_chain_separation(context, chain_context)
}

/// The header of a computed batch output by a runtime. This header is a
/// compressed representation (e.g., hashes instead of full content) of
/// the actual results.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/commitment/executor.go.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ComputeResultsHeader {
    /// Round number.
    pub round: u64,
    /// Hash of the previous block header this batch was computed against.
    pub previous_hash: Hash,

    /// The I/O merkle root.
    #[cbor(optional)]
    pub io_root: Option<Hash>,
    /// The root hash of the state after computing this batch.
    #[cbor(optional)]
    pub state_root: Option<Hash>,
    /// Hash of messages sent from this batch.
    #[cbor(optional)]
    pub messages_hash: Option<Hash>,

    /// The hash of processed incoming messages.
    #[cbor(optional)]
    pub in_msgs_hash: Option<Hash>,
    /// The number of processed incoming messages.
    #[cbor(optional)]
    pub in_msgs_count: u32,
}

impl ComputeResultsHeader {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(self.clone()))
    }

    /// Returns true iff the header is the parent of a child header.
    pub fn is_parent_of(&self, child: &Header) -> bool {
        if self.round != child.round + 1 {
            return false;
        }
        self.previous_hash == child.encoded_hash()
    }
}

/// The executor commitment failure reason.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum ExecutorCommitmentFailure {
    /// Indicates that no failure has occurred.
    #[default]
    FailureNone = 0,

    /// Indicates a generic failure.
    FailureUnknown = 1,

    /// Indicates that batch processing failed due to the state being
    /// unavailable.
    FailureStateUnavailable = 2,
}

/// The header of an executor commitment.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ExecutorCommitmentHeader {
    /// The compute results header.
    pub header: ComputeResultsHeader,

    /// The executor commitment failure reason.
    #[cbor(optional)]
    pub failure: ExecutorCommitmentFailure,

    // Optional fields (may be absent for failure indication).
    #[cbor(optional, rename = "rak_sig")]
    pub rak_signature: Option<Signature>,
}

impl ExecutorCommitmentHeader {
    /// Signs the executor commitment header.
    pub fn sign(
        &self,
        signer: &impl Signer,
        runtime_id: &Namespace,
        chain_context: &String,
    ) -> Result<Signature> {
        let context = executor_commitment_signature_context(runtime_id, chain_context);
        let message = cbor::to_vec(self.clone());

        signer.sign(&context, &message)
    }

    /// Verifies the RAK signature.
    pub fn verify_rak(&self, rak: PublicKey) -> Result<()> {
        let sig = self.rak_signature.ok_or(anyhow!("missing RAK signature"))?;
        let message = cbor::to_vec(self.header.clone());

        sig.verify(&rak, COMPUTE_RESULTS_HEADER_SIGNATURE_CONTEXT, &message)
            .map_err(|_| anyhow!("RAK signature verification failed"))
    }
}

/// A commitment to results of processing a proposed runtime block.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ExecutorCommitment {
    // The public key of the node that generated this commitment.
    pub node_id: PublicKey,

    // The commitment header.
    pub header: ExecutorCommitmentHeader,

    // The commitment header signature.
    #[cbor(rename = "sig")]
    pub signature: Signature,

    // The messages emitted by the runtime.
    //
    // This field is only present in case this commitment belongs to the proposer. In case of
    // the commitment being submitted as equivocation evidence, this field should be omitted.
    #[cbor(optional)]
    pub messages: Vec<Message>,
}

impl ExecutorCommitment {
    /// Signs the executor commitment header and sets the signature on the commitment.
    pub fn sign(
        &mut self,
        signer: &impl Signer,
        runtime_id: &Namespace,
        chain_context: &String,
    ) -> Result<()> {
        let pk = signer.public();
        if self.node_id != pk {
            return Err(anyhow!(
                "node ID does not match signer (ID: {} signer: {})",
                self.node_id,
                pk,
            ));
        }

        self.signature = self.header.sign(signer, runtime_id, chain_context)?;

        Ok(())
    }

    /// Verifies that the header signature is valid.
    pub fn verify(&self, runtime_id: &Namespace, chain_context: &String) -> Result<()> {
        let context = executor_commitment_signature_context(runtime_id, chain_context);
        let message = cbor::to_vec(self.header.clone());

        self.signature
            .verify(&self.node_id, &context, &message)
            .map_err(|_| anyhow!("roothash/commitment: signature verification failed"))
    }

    pub fn validate_basic(&self) -> Result<()> {
        match self.header.failure {
            ExecutorCommitmentFailure::FailureNone => {
                // Ensure header fields are present.
                if self.header.header.io_root.is_none() {
                    return Err(anyhow!("missing IORoot"));
                }
                if self.header.header.state_root.is_none() {
                    return Err(anyhow!("missing StateRoot"));
                }
                if self.header.header.messages_hash.is_none() {
                    return Err(anyhow!("missing messages hash"));
                }
                if self.header.header.in_msgs_hash.is_none() {
                    return Err(anyhow!("missing incoming messages hash"));
                }

                // Validate any included runtime messages.
                for msg in self.messages.iter() {
                    msg.validate_basic()
                        .map_err(|err| anyhow!("bad runtime message: {:?}", err))?;
                }
            }
            ExecutorCommitmentFailure::FailureUnknown
            | ExecutorCommitmentFailure::FailureStateUnavailable => {
                // Ensure header fields are empty.
                if self.header.header.io_root.is_some() {
                    return Err(anyhow!("failure indicating body includes IORoot"));
                }
                if self.header.header.state_root.is_some() {
                    return Err(anyhow!("failure indicating commitment includes StateRoot"));
                }
                if self.header.header.messages_hash.is_some() {
                    return Err(anyhow!(
                        "failure indicating commitment includes MessagesHash"
                    ));
                }
                if self.header.header.in_msgs_hash.is_some()
                    || self.header.header.in_msgs_count != 0
                {
                    return Err(anyhow!(
                        "failure indicating commitment includes InMessagesHash/Count"
                    ));
                }
                // In case of failure indicating commitment make sure RAK signature is empty.
                if self.header.rak_signature.is_some() {
                    return Err(anyhow!("failure indicating body includes RAK signature"));
                }
                // In case of failure indicating commitment make sure messages are empty.
                if !self.messages.is_empty() {
                    return Err(anyhow!("failure indicating body includes messages"));
                }
            }
        }

        Ok(())
    }
}

impl OpenCommitment for ExecutorCommitment {
    fn mostly_equal(&self, other: &Self) -> bool {
        self.to_vote() == other.to_vote()
    }

    fn is_indicating_failure(&self) -> bool {
        self.header.failure != ExecutorCommitmentFailure::FailureNone
    }

    fn to_vote(&self) -> Hash {
        self.header.header.encoded_hash()
    }

    fn to_dd_result(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_hash() {
        // NOTE: These hashes MUST be synced with go/roothash/api/commitment/executor_test.go.
        let empty = ComputeResultsHeader::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")
        );

        let populated = ComputeResultsHeader {
            round: 42,
            previous_hash: empty.encoded_hash(),
            io_root: Some(Hash::empty_hash()),
            state_root: Some(Hash::empty_hash()),
            messages_hash: Some(Hash::empty_hash()),
            in_msgs_hash: Some(Hash::empty_hash()),
            in_msgs_count: 0,
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("8459a9e6e3341cd2df5ada5737469a505baf92397aaa88b7100915324506d843")
        );
    }

    #[test]
    fn test_validate_basic() {
        // NOTE: These hashes MUST be synced with go/roothash/api/commitment/executor_test.go.
        let empty = ComputeResultsHeader::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")
        );

        let body = ExecutorCommitment {
            header: ExecutorCommitmentHeader {
                header: ComputeResultsHeader {
                    round: 42,
                    previous_hash: empty.encoded_hash(),
                    io_root: Some(Hash::empty_hash()),
                    state_root: Some(Hash::empty_hash()),
                    messages_hash: Some(Hash::empty_hash()),
                    in_msgs_hash: Some(Hash::empty_hash()),
                    in_msgs_count: 0,
                },
                failure: ExecutorCommitmentFailure::FailureNone,
                rak_signature: None,
            },
            messages: vec![],
            node_id: PublicKey::default(),
            signature: Signature::default(),
        };

        let tcs: Vec<(&str, fn(&mut ExecutorCommitment), bool)> = vec![
            (
                "Ok",
                |ec: &mut ExecutorCommitment| {
                    ec.header.header.round -= 1;
                },
                false,
            ),
            (
                "Bad io_root",
                |ec: &mut ExecutorCommitment| ec.header.header.io_root = None,
                true,
            ),
            (
                "Bad state_root",
                |ec: &mut ExecutorCommitment| ec.header.header.state_root = None,
                true,
            ),
            (
                "Bad messages_hash",
                |ec: &mut ExecutorCommitment| ec.header.header.messages_hash = None,
                true,
            ),
            (
                "Bad Failure (existing io_root)",
                |ec: &mut ExecutorCommitment| {
                    ec.header.failure = ExecutorCommitmentFailure::FailureUnknown;
                    // ec.header.compute_results_header.io_root is set.
                    ec.header.header.state_root = None;
                    ec.header.header.messages_hash = None;
                    ec.header.header.in_msgs_hash = None;
                },
                true,
            ),
            (
                "Bad Failure (existing state_root)",
                |ec: &mut ExecutorCommitment| {
                    ec.header.failure = ExecutorCommitmentFailure::FailureUnknown;
                    ec.header.header.io_root = None;
                    // ec.header.compute_results_header.state_root is set.
                    ec.header.header.messages_hash = None;
                    ec.header.header.in_msgs_hash = None;
                },
                true,
            ),
            (
                "Bad Failure (existing messages_hash)",
                |ec: &mut ExecutorCommitment| {
                    ec.header.failure = ExecutorCommitmentFailure::FailureUnknown;
                    ec.header.header.io_root = None;
                    ec.header.header.state_root = None;
                    // ec.header.compute_results_header.messages_hash is set.
                    ec.header.header.in_msgs_hash = None;
                },
                true,
            ),
            (
                "Bad Failure (existing in_msgs_hash)",
                |ec: &mut ExecutorCommitment| {
                    ec.header.failure = ExecutorCommitmentFailure::FailureUnknown;
                    ec.header.header.io_root = None;
                    ec.header.header.state_root = None;
                    ec.header.header.messages_hash = None;
                    // ec.header.compute_results_header.in_msgs_hash is set.
                },
                true,
            ),
            (
                "Ok Failure",
                |ec: &mut ExecutorCommitment| {
                    ec.header.failure = ExecutorCommitmentFailure::FailureUnknown;
                },
                true,
            ),
        ];

        for (name, f, should_err) in tcs {
            let mut b = body.clone();
            f(&mut b);
            let res = b.validate_basic();
            assert_eq!(res.is_err(), should_err, "validate_basic({})", name)
        }
    }
}
