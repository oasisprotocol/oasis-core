//! Contract Interface.
use std::convert::TryFrom;

use bytes::B256;
use error::Error;

use ekiden_common_api as api;

/// The unserialized representation of a contract.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    /// Globally unique long term identifier of the Contract.
    pub id: B256,

    /// Storage service ID associated with the Contract.
    pub store_id: B256,

    /// The contract code body.
    pub code: Vec<u8>,

    // XXX: "tokens" for advertisement (PR #2), in to be specified units.
    /// The minimum stake required by the contract.
    pub minimum_bond: u64,

    pub mode_nondeterministic: bool,

    pub features_sgx: bool,

    /// Number of tokens/second of contract instance advertisement.
    pub advertisement_rate: u64,

    /// The size of the computation group this contract will be sharded out to.
    pub replica_group_size: u64,

    /// The size of the storage grou pthis contract will use.
    pub storage_group_size: u64,
    // XXX: "budget" (PR #2), in to be specified units.

    // XXX: Other critera
}

impl TryFrom<api::Contract> for Contract {
    /// try_from Converts a protobuf `common::api::Contract` into a contract.
    type Error = super::error::Error;
    fn try_from(a: api::Contract) -> Result<Self, Error> {
        let id = a.get_id();
        let id = B256::from_slice(&id);

        let sid = a.get_store_id();
        let sid = B256::from_slice(&sid);

        Ok(Contract {
            id: id,
            store_id: sid,
            code: a.get_code().to_vec(),
            minimum_bond: a.minimum_bond,
            mode_nondeterministic: a.get_mode() == api::Contract_Mode::Nondeterministic,
            features_sgx: a.get_features()
                .iter()
                .any(|f| *f == api::Contract_Features::SGX),
            advertisement_rate: a.advertisement_rate,
            replica_group_size: a.replica_group_size,
            storage_group_size: a.storage_group_size,
        })
    }
}

impl Into<api::Contract> for Contract {
    /// into Converts a contract into a protobuf `common::api::Contract` representation.
    fn into(self) -> api::Contract {
        let mut c = api::Contract::new();
        c.set_id(self.id.to_vec());
        c.set_store_id(self.store_id.to_vec());
        c.set_code(self.code);
        c.set_minimum_bond(self.minimum_bond);
        if self.mode_nondeterministic {
            c.set_mode(api::Contract_Mode::Nondeterministic);
        }
        if self.features_sgx {
            c.set_features(vec![api::Contract_Features::SGX]);
        }
        c.set_advertisement_rate(self.advertisement_rate);
        c.set_replica_group_size(self.replica_group_size);
        c.set_storage_group_size(self.storage_group_size);
        c
    }
}
