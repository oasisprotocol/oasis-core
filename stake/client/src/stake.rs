//! Entity stake gRPC client.
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, Environment};

use ekiden_common::bytes::B256;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::node::Node;
use ekiden_stake_api as api;
use ekiden_stake_base::{EscrowAccountIdType, EscrowAccountStatus, StakeEscrowBackend, StakeStatus};

/// Stake client implements the Escrow interface.
pub struct StakeClient(api::StakeClient);

impl StakeClient {
    pub fn new(channel: Channel) -> Self {
        StakeClient(api::StakeClient::new(channel))
    }

    pub fn from_node(node: &Node, environment: Arc<Environment>) -> Self {
        StakeClient::new(node.connect(environment))
    }
}

impl StakeEscrowBackend for StakeClient {
    fn deposit_stake(&self, sender: B256, amount: u64) -> BoxFuture<()> {
        let mut request = api::DepositStakeRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_amount(amount);
        match self.0.deposit_stake_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_stake_status(&self, sender: B256) -> BoxFuture<StakeStatus> {
        let mut request = api::GetStakeStatusRequest::new();
        request.set_msg_sender(sender.to_vec());
        match self.0.get_stake_status_async(&request) {
            Ok(f) => Box::new(f.map(|response| StakeStatus {
                total_stake: response.total_stake,
                escrowed: response.escrowed_stake,
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn transfer_stake(&self, sender: B256, target: B256, amount: u64) -> BoxFuture<()> {
        let mut request = api::TransferStakeRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_target(target.to_vec());
        request.set_amount(amount);
        match self.0.transfer_stake_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ()).map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn withdraw_stake(&self, sender: B256, amount_requested: u64) -> BoxFuture<u64> {
        let mut request = api::WithdrawStakeRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_amount_requested(amount_requested);
        match self.0.withdraw_stake_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.amount_returned)
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn allocate_escrow(
        &self,
        sender: B256,
        target: B256,
        amount: u64,
    ) -> BoxFuture<EscrowAccountIdType> {
        let mut request = api::AllocateEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_target(target.to_vec());
        request.set_escrow_amount(amount);
        match self.0.allocate_escrow_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|response| Ok(EscrowAccountIdType::from_vec(response.escrow_id)?)),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn list_active_escrows(&self, sender: B256) -> BoxFuture<Vec<EscrowAccountStatus>> {
        let mut request = api::ListActiveEscrowsRequest::new();
        request.set_msg_sender(sender.to_vec());
        match self.0.list_active_escrows_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |mut response| {
                    let mut response = response.take_escrows().into_vec();
                    let result: Result<_> = response
                        .drain(..)
                        .map(|escrow| {
                            Ok(EscrowAccountStatus::new(
                                EscrowAccountIdType::from_vec(escrow.escrow_id)?,
                                B256::try_from(&escrow.entity)?,
                                escrow.amount,
                            ))
                        })
                        .collect();

                    result
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn fetch_escrow_by_id(&self, id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus> {
        let mut request = api::FetchEscrowByIdRequest::new();
        request.set_escrow_id(id.to_vec());
        match self.0.fetch_escrow_by_id_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |mut response| {
                    let escrow = response.take_escrow();
                    Ok(EscrowAccountStatus::new(
                        EscrowAccountIdType::from_vec(escrow.escrow_id)?,
                        B256::try_from(&escrow.entity)?,
                        escrow.amount,
                    ))
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn take_and_release_escrow(
        &self,
        sender: B256,
        id: EscrowAccountIdType,
        amount_requested: u64,
    ) -> BoxFuture<u64> {
        let mut request = api::TakeAndReleaseEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_escrow_id(id.to_vec());
        request.set_amount_requested(amount_requested);
        match self.0.take_and_release_escrow_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.amount_taken)
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }
}
