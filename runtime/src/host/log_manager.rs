use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::protocol::Protocol;

use super::{host_rpc_call, Error};

/// Name of the local RPC endpoint for the log manager.
pub const LOCAL_RPC_ENDPOINT_LOG_MANAGER: &str = "log-manager";

/// Name of the LogGet method.
pub const METHOD_LOG_GET: &str = "LogGet";

/// Log manager interface.
#[async_trait]
pub trait LogManager: Send + Sync {
    /// Request to host to fetch logs.
    ///
    /// The `PermissionLogView` permission is required to call this method.
    async fn log_get(&self, args: LogGetRequest) -> Result<LogGetResponse, Error>;
}

#[async_trait]
impl LogManager for Protocol {
    async fn log_get(&self, args: LogGetRequest) -> Result<LogGetResponse, Error> {
        host_rpc_call(self, LOCAL_RPC_ENDPOINT_LOG_MANAGER, METHOD_LOG_GET, args).await
    }
}

/// Request to fetch logs.
///
/// The `PermissionLogView` permission is required to call this method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct LogGetRequest {
    /// Labels to filter the bundles by. All labels must match and only the first bundle is used.
    pub labels: BTreeMap<String, String>,
    /// Identifier of the component in the bundle.
    pub component_id: String,
    /// An optional UNIX timestamp to filter log entries by. Only entries with higher timestamps
    /// will be returned.
    #[cbor(optional)]
    pub since: u64,
}

/// Response from the LogGet method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct LogGetResponse {
    /// Log lines for the given component.
    pub logs: Vec<String>,
}
