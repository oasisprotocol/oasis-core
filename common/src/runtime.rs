//! Runtime Interface.
use std::convert::TryFrom;

use bytes::B256;
use error::Error;

use ekiden_common_api as api;

/// The unserialized representation of a runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runtime {
    /// Globally unique long term identifier of the Runtime.
    pub id: B256,

    /// Storage service ID associated with the Runtime.
    pub store_id: B256,

    /// The runtime code body.
    pub code: Vec<u8>,

    // XXX: "tokens" for advertisement (PR #2), in to be specified units.
    /// The minimum stake required by the runtime.
    pub minimum_bond: u64,

    pub mode_nondeterministic: bool,

    pub features_sgx: bool,

    /// Number of tokens/second of runtime instance advertisement.
    pub advertisement_rate: u64,

    /// The size of the computation group this runtime will be sharded out to.
    pub replica_group_size: u64,
    /// The size of the discrepancy resolution replica group.
    pub replica_group_backup_size: u64,
    /// The allowed number of stragglers.
    pub replica_allowed_stragglers: u64,

    /// The size of the storage group this runtime will use.
    pub storage_group_size: u64,
    // XXX: "budget" (PR #2), in to be specified units.

    // XXX: Other critera
}

impl TryFrom<api::Runtime> for Runtime {
    /// try_from Converts a protobuf `common::api::Runtime` into a runtime.
    type Error = super::error::Error;
    fn try_from(a: api::Runtime) -> Result<Self, Error> {
        let id = a.get_id();
        let id = B256::from_slice(&id);

        let sid = a.get_store_id();
        let sid = B256::from_slice(&sid);

        Ok(Runtime {
            id: id,
            store_id: sid,
            code: a.get_code().to_vec(),
            minimum_bond: a.minimum_bond,
            mode_nondeterministic: a.get_mode() == api::Runtime_Mode::Nondeterministic,
            features_sgx: a.get_features()
                .iter()
                .any(|f| *f == api::Runtime_Features::SGX),
            advertisement_rate: a.advertisement_rate,
            replica_group_size: a.replica_group_size,
            replica_group_backup_size: a.replica_group_backup_size,
            replica_allowed_stragglers: a.replica_allowed_stragglers,
            storage_group_size: a.storage_group_size,
        })
    }
}

impl Into<api::Runtime> for Runtime {
    /// into Converts a runtime into a protobuf `common::api::Runtime` representation.
    fn into(self) -> api::Runtime {
        let mut c = api::Runtime::new();
        c.set_id(self.id.to_vec());
        c.set_store_id(self.store_id.to_vec());
        c.set_code(self.code);
        c.set_minimum_bond(self.minimum_bond);
        if self.mode_nondeterministic {
            c.set_mode(api::Runtime_Mode::Nondeterministic);
        }
        if self.features_sgx {
            c.set_features(vec![api::Runtime_Features::SGX]);
        }
        c.set_advertisement_rate(self.advertisement_rate);
        c.set_replica_group_size(self.replica_group_size);
        c.set_replica_group_backup_size(self.replica_group_backup_size);
        c.set_replica_allowed_stragglers(self.replica_allowed_stragglers);
        c.set_storage_group_size(self.storage_group_size);
        c
    }
}
