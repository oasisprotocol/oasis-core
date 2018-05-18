//! Stake escrow backend interface.
use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::futures::BoxFuture;

use ekiden_stake_api as api;

/// Stake escrow backend implementing the Ekiden stake escrow interface.
pub trait StakeEscrowBackend: Send + Sync {
    /// Stake 
    fn deposit_stake(&self, msg_sender: Entity, amount: u64)
                     -> BoxFuture<()>;
    fn get_stake_status(&self, msg_sender: Entity)
                        -> BoxFuture<(u64, u64)>;
    fn withdraw_stake(&self, msg_sender: Entity, amount_requested: u64)
                      -> BoxFuture<u64>;
    fn allocate_escrow(&self, msg_sender: Entity,
                       entity: Entity, escrow_amount: u64)
                       -> BoxFuture<B256>;
    fn list_active_escrows(&self, msg_sender: Entity)
                           -> BoxFuture<Vec<api::EscrowData>>;
    fn fetch_escrow_by_id(&self, id: B256)
                          -> BoxFuture<api::EscrowData>;
    fn take_and_release_escrow(&self, msg_sender: Entity,
                               id: B256, amount_requested: u64)
                               -> BoxFuture<u64>;
}
