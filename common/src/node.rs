//! Node Interface.
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(not(target_env = "sgx"))]
use grpcio;

use address::Address;
use bytes::B256;
use error::Error;

use ekiden_common_api as api;

/// Node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// A public key identifying the node.
    pub id: B256,
    /// The public key identifying the `Entity` controlling the node.
    pub entity_id: B256,
    /// The epoch in which this nodes committment expires.
    pub expiration: u64,
    /// The list of `Address`es at which the node can be reached.
    pub addresses: Vec<Address>,
    //TODO: define the reference to a stake.
    pub stake: Vec<u8>,
}

impl TryFrom<api::Node> for Node {
    /// try_from Converts a protobuf `common::api::Node` into a node.
    type Error = super::error::Error;
    fn try_from(a: api::Node) -> Result<Self, Error> {
        let id = a.get_id();
        let id = B256::from_slice(&id);

        let eid = a.get_entity_id();
        let eid = B256::from_slice(&eid);

        let mut addresses = a.get_addresses()
            .into_iter()
            .map(|addr| Address::try_from(addr.to_owned()));
        if addresses.any(|a| a.is_err()) {
            Err(Error::new("Bad Address"))
        } else {
            Ok(Node {
                id: id,
                entity_id: eid,
                expiration: a.expiration,
                addresses: addresses.map(|a| a.unwrap()).collect(),
                stake: a.get_stake().to_vec(),
            })
        }
    }
}

impl Into<api::Node> for Node {
    /// into Converts a node into a protobuf `common::api::Node` representation.
    fn into(self) -> api::Node {
        let mut n = api::Node::new();
        n.set_id(self.id.to_vec());
        n.set_entity_id(self.entity_id.to_vec());
        n.set_expiration(self.expiration);
        n.set_addresses(self.addresses.iter().map(|a| a.to_owned().into()).collect());
        n.set_stake(self.stake.clone());
        n
    }
}

#[cfg(not(target_env = "sgx"))]
impl Node {
    pub fn connect(self, env: Arc<grpcio::Environment>) -> grpcio::Channel {
        let builder = grpcio::ChannelBuilder::new(env.clone());
        // TODO: try all addresses
        let address = self.addresses[0];
        // TODO: node identity pub-keys should be used to construct a cert to allow secure_connect.
        builder.connect(&format!("{}", address))
    }
}
