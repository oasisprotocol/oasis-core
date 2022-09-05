use crate::common::{crypto::signature::Signed, quantity::Quantity};

pub const SIGNATURE_CONTEXT: &[u8] = b"oasis-core/consensus: tx for chain ";

/// Unsigned consensus transaction.
#[derive(Debug, cbor::Encode, cbor::Decode)]
#[cbor(no_default)]
pub struct Transaction {
    /// Nonce to prevent replay.
    pub nonce: u64,
    /// Optional fee that the sender commits to pay to execute this transaction.
    pub fee: Option<Fee>,

    /// Method that should be called.
    pub method: MethodName,
    /// Method call body.
    pub body: cbor::Value,
}

/// Signed consensus transaction.
pub type SignedTransaction = Signed;

/// Consensus transaction fee the sender wishes to pay for operations which
/// require a fee to be paid to validators.
#[derive(Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Fee {
    /// Fee amount to be paid.
    pub amount: Quantity,
    /// Maximum gas that a transaction can use.
    pub gas: Gas,
}

/// Consensus gas representation.
pub type Gas = u64;

/// Method name.
pub type MethodName = String;

/// Proof of transaction inclusion in a block.
#[derive(Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Proof {
    /// Block height at which the transaction was published.
    pub height: u64,
    /// Actual raw proof.
    pub raw_proof: Vec<u8>,
}
