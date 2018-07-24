//! Entity stake gRPC client.
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::Channel;

use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_stake_api as api;
use ekiden_stake_base::{AmountType, StakeEscrowBackend, StakeStatus};

/// Stake client implements the Escrow interface.
pub struct StakeClient(api::StakeClient);

impl StakeClient {
    pub fn new(channel: Channel) -> Self {
        StakeClient(api::StakeClient::new(channel))
    }

    pub fn from_node(
        node: &Node,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        StakeClient::new(node.connect(environment, identity))
    }
}

impl StakeEscrowBackend for StakeClient {
    fn link_to_dispute_resolution(&self, address: B256) -> BoxFuture<(bool)> {
        let mut request = api::LinkToDisputeResolutionRequest::new();
        request.set_address(address.to_vec());
        match self.0.link_to_dispute_resolution_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn link_to_entity_registry(&self, address: B256) -> BoxFuture<(bool)> {
        let mut request = api::LinkToEntityRegistryRequest::new();
        request.set_address(address.to_vec());
        match self.0.link_to_entity_registry_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_name(&self) -> BoxFuture<String> {
        let request = api::GetNameRequest::new();
        match self.0.get_name_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_name().to_string())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_symbol(&self) -> BoxFuture<String> {
        let request = api::GetSymbolRequest::new();
        match self.0.get_symbol_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_symbol().to_string())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_decimals(&self) -> BoxFuture<u8> {
        let request = api::GetDecimalsRequest::new();
        match self.0.get_decimals_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_decimals() as u8)
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_total_supply(&self) -> BoxFuture<AmountType> {
        let request = api::GetTotalSupplyRequest::new();
        match self.0.get_total_supply_async(&request) {
            Ok(f) => Box::new(f.map(|response| {
                AmountType::from_little_endian(response.get_total_supply())
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_stake_status(&self, sender: B256) -> BoxFuture<StakeStatus> {
        let mut request = api::GetStakeStatusRequest::new();
        request.set_owner(sender.to_vec());
        match self.0.get_stake_status_async(&request) {
            Ok(f) => Box::new(f.map(|response| StakeStatus {
                total_stake: AmountType::from_little_endian(&response.total_stake),
                escrowed: AmountType::from_little_endian(&response.escrowed_stake),
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn balance_of(&self, owner: B256) -> BoxFuture<AmountType> {
        let mut request = api::BalanceOfRequest::new();
        request.set_owner(owner.to_vec());
        match self.0.balance_of_async(&request) {
            Ok(f) => Box::new(f.map(|response| {
                AmountType::from_little_endian(response.get_available_balance())
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn transfer(
        &self,
        sender: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<(bool)> {
        let mut request = api::TransferRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_destination_address(destination_address.to_vec());
        request.set_value(value.to_vec());
        match self.0.transfer_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn transfer_from(
        &self,
        msg_sender: B256,
        source_address: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let mut request = api::TransferFromRequest::new();
        request.set_msg_sender(msg_sender.to_vec());
        request.set_source_address(source_address.to_vec());
        request.set_destination_address(destination_address.to_vec());
        request.set_value(value.to_vec());
        match self.0.transfer_from_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn approve(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let mut request = api::ApproveRequest::new();
        request.set_msg_sender(msg_sender.to_vec());
        request.set_spender_address(spender_address.to_vec());
        request.set_value(value.to_vec());
        match self.0.approve_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn approve_and_call(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
        extra_data: Vec<u8>,
    ) -> BoxFuture<bool> {
        let mut request = api::ApproveAndCallRequest::new();
        request.set_msg_sender(msg_sender.to_vec());
        request.set_spender_address(spender_address.to_vec());
        request.set_value(value.to_vec());
        request.set_extra_data(extra_data);
        match self.0.approve_and_call_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn allowance(&self, owner: B256, spender: B256) -> BoxFuture<AmountType> {
        let mut request = api::AllowanceRequest::new();
        request.set_owner_address(owner.to_vec());
        request.set_spender_address(spender.to_vec());
        match self.0.allowance_async(&request) {
            Ok(f) => Box::new(f.map(|response| {
                AmountType::from_little_endian(response.get_remaining())
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn burn(&self, msg_sender: B256, value: AmountType) -> BoxFuture<bool> {
        let mut request = api::BurnRequest::new();
        request.set_msg_sender(msg_sender.to_vec());
        request.set_value(value.to_vec());
        match self.0.burn_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn burn_from(&self, msg_sender: B256, owner: B256, value: AmountType) -> BoxFuture<bool> {
        let mut request = api::BurnFromRequest::new();
        request.set_msg_sender(msg_sender.to_vec());
        request.set_owner_address(owner.to_vec());
        request.set_value(value.to_vec());
        match self.0.burn_from_async(&request) {
            Ok(f) => Box::new(
                f.map(|response| response.get_success())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn add_escrow(&self, sender: B256, amount: AmountType) -> BoxFuture<AmountType> {
        let mut request = api::AddEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_escrow_amount(amount.to_vec());
        match self.0.add_escrow_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |response| {
                    Ok(AmountType::from_little_endian(&response.get_total_escrow_so_far()))
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn fetch_escrow_amount(&self, owner: B256) -> BoxFuture<AmountType> {
        let mut request = api::FetchEscrowAmountRequest::new();
        request.set_owner(owner.to_vec());
        match self.0.fetch_escrow_amount_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|response| {
                        Ok(AmountType::from_little_endian(&response.get_amount()))
                    }),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn take_escrow(
        &self,
        sender: B256,
        owner: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let mut request = api::TakeEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_owner(owner.to_vec());
        request.set_amount_requested(amount_requested.to_vec());
        match self.0.take_escrow_async(&request) {
            Ok(f) => Box::new(f.map(|response| {
                AmountType::from_little_endian(response.get_amount_taken())
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn release_escrow(&self, sender: B256, owner: B256) -> BoxFuture<AmountType> {
        let mut request = api::ReleaseEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_owner(owner.to_vec());
        match self.0.release_escrow_async(&request) {
            Ok(f) => Box::new(f.map(|response| {
                AmountType::from_little_endian(response.get_amount_returned())
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }
}
