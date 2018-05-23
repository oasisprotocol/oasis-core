//! Contract registry gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, Environment};

use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, stream, BoxFuture, BoxStream, Future, Stream};
use ekiden_common::node::Node;
use ekiden_common::signature::Signed;
use ekiden_registry_api as api;
use ekiden_registry_base::ContractRegistryBackend;

/// Scheduler client implements the Scheduler interface.
pub struct ContractRegistryClient(api::ContractRegistryClient);

impl ContractRegistryClient {
    pub fn new(channel: Channel) -> Self {
        ContractRegistryClient(api::ContractRegistryClient::new(channel))
    }

    pub fn from_node(node: &Node, environment: Arc<Environment>) -> Self {
        ContractRegistryClient::new(node.connect(environment))
    }
}

impl ContractRegistryBackend for ContractRegistryClient {
    fn register_contract(&self, contract: Signed<Contract>) -> BoxFuture<()> {
        let mut request = api::RegisterContractRequest::new();
        request.set_contract(contract.get_value_unsafe().clone().into());
        request.set_signature(contract.signature.into());
        match self.0.register_contract_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_contract(&self, id: B256) -> BoxFuture<Contract> {
        let mut request = api::ContractRequest::new();
        request.set_id(id.to_vec());
        match self.0.get_contract_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|mut response| Ok(Contract::try_from(response.take_contract())?)),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_contracts(&self) -> BoxStream<Contract> {
        let request = api::ContractsRequest::new();
        match self.0.get_contracts(&request) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(response) => Ok(Contract::try_from(response.get_contract().to_owned())?),
                Err(error) => Err(Error::new(error.description())),
            })),
            Err(error) => Box::new(stream::once::<Contract, _>(Err(Error::new(
                error.description(),
            )))),
        }
    }
}
