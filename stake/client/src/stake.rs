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
use ekiden_stake_base::{AmountType, EscrowAccountIdType, EscrowAccountIterator,
                        EscrowAccountStatus, StakeEscrowBackend, StakeStatus};

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

    fn allocate_escrow(
        &self,
        sender: B256,
        target: B256,
        amount: AmountType,
        aux: B256,
    ) -> BoxFuture<EscrowAccountIdType> {
        let mut request = api::AllocateEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_target(target.to_vec());
        request.set_escrow_amount(amount.to_vec());
        request.set_aux(aux.to_vec());
        match self.0.allocate_escrow_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|response| Ok(EscrowAccountIdType::from_vec(response.escrow_id)?)),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn list_active_escrows_iterator(&self, owner: B256) -> BoxFuture<EscrowAccountIterator> {
        let mut request = api::ListActiveEscrowsIteratorRequest::new();
        request.set_owner(owner.to_vec());
        match self.0.list_active_escrows_iterator_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                move |response| {
                    Ok(EscrowAccountIterator::new(
                        response.get_has_next(),
                        owner.clone(),
                        B256::try_from(response.get_state())?,
                    ))
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn list_active_escrows_get(
        &self,
        it: EscrowAccountIterator,
    ) -> BoxFuture<(EscrowAccountStatus, EscrowAccountIterator)> {
        assert!(it.has_next);
        let mut request = api::ListActiveEscrowsGetRequest::new();
        request.set_owner(it.owner.to_vec());
        request.set_state(it.state.to_vec());
        match self.0.list_active_escrows_get_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                move |response| {
                    let status = EscrowAccountStatus::new(
                        EscrowAccountIdType::from_slice(response.get_escrow_id())?,
                        B256::try_from(&response.get_target())?,
                        AmountType::from_little_endian(&response.get_amount()),
                        B256::try_from(&response.get_aux())?,
                    );
                    let new_it = EscrowAccountIterator::new(
                        response.get_has_next(),
                        it.owner.clone(),
                        B256::try_from(&response.get_state())?,
                    );
                    Ok((status, new_it))
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
                |response| {
                    Ok(EscrowAccountStatus::new(
                        EscrowAccountIdType::from_slice(response.get_escrow_id())?,
                        B256::try_from(&response.target)?,
                        AmountType::from_little_endian(&response.get_amount()),
                        B256::try_from(&response.aux)?,
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
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let mut request = api::TakeAndReleaseEscrowRequest::new();
        request.set_msg_sender(sender.to_vec());
        request.set_escrow_id(id.to_vec());
        request.set_amount_requested(amount_requested.to_vec());
        match self.0.take_and_release_escrow_async(&request) {
            Ok(f) => Box::new(f.map(|response| {
                AmountType::from_little_endian(response.get_amount_taken())
            }).map_err(|error| Error::new(error.description()))),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }
}
