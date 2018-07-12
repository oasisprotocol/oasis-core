//! Tendermint transaction.
use super::consensus::ConsensusTransaction;

/// Possible Tendermint transactions supported by the ABCI application.
#[derive(Clone, Serialize, Deserialize)]
pub enum Transaction {
    Consensus(ConsensusTransaction),
}
