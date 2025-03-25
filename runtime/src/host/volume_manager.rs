use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::protocol::Protocol;

use super::{host_rpc_call, Error};

/// Name of the local RPC endpoint for the volume manager.
pub const LOCAL_RPC_ENDPOINT_VOLUME_MANAGER: &str = "volume-manager";

/// Name of the VolumeAdd method.
pub const METHOD_VOLUME_ADD: &str = "VolumeAdd";
/// Name of the VolumeRemove method.
pub const METHOD_VOLUME_REMOVE: &str = "VolumeRemove";
/// Name of the VolumeList method.
pub const METHOD_VOLUME_LIST: &str = "VolumeList";

/// Volume manager interface.
#[async_trait]
pub trait VolumeManager: Send + Sync {
    /// Request to host to add a volume.
    ///
    /// The `PermissionVolumeAdd` permission is required to call this method.
    async fn volume_add(&self, args: VolumeAddRequest) -> Result<VolumeAddResponse, Error>;

    /// Request to host to remove volumes.
    ///
    /// The `PermissionVolumeRemove` permission is required to call this method.
    async fn volume_remove(&self, args: VolumeRemoveRequest)
        -> Result<VolumeRemoveResponse, Error>;

    /// Request to host to list volumes.
    ///
    /// The `PermissionVolumeAdd` permission is required to call this method.
    async fn volume_list(&self, args: VolumeListRequest) -> Result<VolumeListResponse, Error>;
}

#[async_trait]
impl VolumeManager for Protocol {
    async fn volume_add(&self, args: VolumeAddRequest) -> Result<VolumeAddResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_VOLUME_MANAGER,
            METHOD_VOLUME_ADD,
            args,
        )
        .await
    }

    async fn volume_remove(
        &self,
        args: VolumeRemoveRequest,
    ) -> Result<VolumeRemoveResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_VOLUME_MANAGER,
            METHOD_VOLUME_REMOVE,
            args,
        )
        .await
    }

    async fn volume_list(&self, args: VolumeListRequest) -> Result<VolumeListResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_VOLUME_MANAGER,
            METHOD_VOLUME_LIST,
            args,
        )
        .await
    }
}

/// Request to add a volume.
///
/// The `PermissionVolumeAdd` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeAddRequest {
    /// Labels to tag the volume with so it can later be found.
    pub labels: BTreeMap<String, String>,
}

/// Response from the VolumeAdd method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeAddResponse {
    /// Unique volume identifier.
    pub id: String,
}

/// Request to remove volumes.
///
/// The `PermissionVolumeRemove` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeRemoveRequest {
    /// Labels to filter the volumes by.
    pub labels: BTreeMap<String, String>,
}

/// Response from the VolumeRemove method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeRemoveResponse {}

// Request to list volumes.
//
// The `PermissionVolumeAdd` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeListRequest {
    /// Labels to filter the volumes by.
    pub labels: BTreeMap<String, String>,
}

/// Response from the VolumeList method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeListResponse {
    #[cbor(optional)]
    pub volumes: Vec<VolumeInfo>,
}

/// Volume information.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct VolumeInfo {
    /// Unique volume identifier.
    pub id: String,
    /// Labels assigned to this volume.
    pub labels: BTreeMap<String, String>,
}
