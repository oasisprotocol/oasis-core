use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::{common::crypto::hash::Hash, protocol::Protocol};

use super::{host_rpc_call, Error};

/// Name of the local RPC endpoint for the bundle manager.
pub const LOCAL_RPC_ENDPOINT_BUNDLE_MANAGER: &str = "bundle-manager";

/// Name of the BundleWrite method.
pub const METHOD_BUNDLE_WRITE: &str = "BundleWrite";
/// Name of the BundleAdd method.
pub const METHOD_BUNDLE_ADD: &str = "BundleAdd";
/// Name of the BundleRemove method.
pub const METHOD_BUNDLE_REMOVE: &str = "BundleRemove";
/// Name of the BundleList method.
pub const METHOD_BUNDLE_LIST: &str = "BundleList";

/// Name of the special label that identifies the instance.
pub const LABEL_INSTANCE_ID: &str = "net.oasis.instance_id";

/// Bundle manager interface.
#[async_trait]
pub trait BundleManager: Send + Sync {
    /// Request to host to write a chunk of the bundle to a temporary file.
    ///
    /// The `PermissionBundleAdd` permission is required to call this method.
    async fn bundle_write(&self, args: BundleWriteRequest) -> Result<BundleWriteResponse, Error>;

    /// Request to host to add a specific bundle to the host.
    ///
    /// The `PermissionBundleAdd` permission is required to call this method.
    async fn bundle_add(&self, args: BundleAddRequest) -> Result<BundleAddResponse, Error>;

    /// Request to host to remove a specific component. Only ROFL components added by this component
    /// can be removed.
    ///
    /// The `PermissionBundleRemove` permission is required to call this method.
    async fn bundle_remove(&self, args: BundleRemoveRequest)
        -> Result<BundleRemoveResponse, Error>;

    /// Request to host to list all bundles.
    ///
    /// The `PermissionBundleAdd` permission is required to call this method.
    async fn bundle_list(&self, args: BundleListRequest) -> Result<BundleListResponse, Error>;
}

#[async_trait]
impl BundleManager for Protocol {
    async fn bundle_write(&self, args: BundleWriteRequest) -> Result<BundleWriteResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_BUNDLE_MANAGER,
            METHOD_BUNDLE_WRITE,
            args,
        )
        .await
    }

    async fn bundle_add(&self, args: BundleAddRequest) -> Result<BundleAddResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_BUNDLE_MANAGER,
            METHOD_BUNDLE_ADD,
            args,
        )
        .await
    }

    async fn bundle_remove(
        &self,
        args: BundleRemoveRequest,
    ) -> Result<BundleRemoveResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_BUNDLE_MANAGER,
            METHOD_BUNDLE_REMOVE,
            args,
        )
        .await
    }

    async fn bundle_list(&self, args: BundleListRequest) -> Result<BundleListResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_BUNDLE_MANAGER,
            METHOD_BUNDLE_LIST,
            args,
        )
        .await
    }
}

/// Request to host to write a chunk of the bundle to a temporary file.
///
/// The `PermissionBundleAdd` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleWriteRequest {
    /// Temporary file name to use on the host while writing the bundle.
    pub temporary_name: String,
    /// Optional flag which specifies that the temporary file should be recreated. If the file
    /// exists and this flag is set to true, it will be truncated. If the flag is set to false, any
    /// content will be appended to the existing file.
    pub create: bool,
    /// Data that should be appended to the temporary file.
    pub data: Vec<u8>,
}

/// Response form the BundleWrite method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleWriteResponse {}

/// Request to host to add a specific bundle to the host.
///
/// The `PermissionBundleAdd` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleAddRequest {
    /// Temporary file name to read the bundle from. The file must have previously been created by
    /// using `BundleWriteRequest`.
    ///
    /// The file must be a valid bundle.
    pub temporary_name: String,
    /// Expected hash of the manifest contained inside the bundle.
    pub manifest_hash: Hash,
    /// Labels to tag the bundle with.
    ///
    /// Note that the host will assign a random component identifier to these components, so one
    /// should use labels to later be able to find them.
    ///
    /// Use the special `LABEL_INSTANCE_ID` label to specify a deterministic instance ID.
    pub labels: BTreeMap<String, String>,
}

/// Response form the BundleAdd method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleAddResponse {}

/// Request to host to remove a specific component. Only ROFL components added by this component can
/// be removed.
///
/// The `PermissionBundleRemove` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleRemoveRequest {
    /// Labels to filter the components by.
    pub labels: BTreeMap<String, String>,
}

/// Response form the BundleRemove method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleRemoveResponse {}

/// Request to host to list all bundles.
///
/// The `PermissionBundleAdd` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleListRequest {
    /// Labels to filter the components by.
    pub labels: BTreeMap<String, String>,
}

/// Response from host to list all bundles.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleListResponse {
    /// The resulting bundles.
    #[cbor(optional)]
    pub bundles: Vec<BundleInfo>,
}

/// Bundle information.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct BundleInfo {
    /// Hash of the manifest.
    pub manifest_hash: Hash,
    /// List of all components in this bundle.
    pub components: Vec<ComponentInfo>,
    /// Labels assigned to this bundle.
    pub labels: BTreeMap<String, String>,
}

/// Component information.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct ComponentInfo {
    /// Component name.
    pub name: String,
}
