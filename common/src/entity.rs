//! Entity Interface.
use std::convert::TryFrom;

use bytes::{B256, H160};
use error::Error;

use ekiden_common_api as api;

/// Entity. An entity controls one or multiple Nodes / services.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// The public key identifying this Entity.
    pub id: B256,
    /// The ethereum address of this Entity.
    pub eth_address: Option<H160>,
}

impl Entity {
    pub fn for_local_test(id: B256) -> Entity {
        Entity {
            id: id,
            eth_address: None,
        }
    }
}

impl TryFrom<api::Entity> for Entity {
    /// try_from Converts a protobuf `common::api::Entity` into an Entity.
    type Error = super::error::Error;
    fn try_from(a: api::Entity) -> Result<Self, Error> {
        let id = B256::try_from(a.get_id())?;
        let eth_address = match H160::try_from(a.get_eth_address()) {
            Ok(addr) => Some(addr),
            Err(_) => None,
        };

        Ok(Entity {
            id: id,
            eth_address: eth_address,
        })
    }
}

impl Into<api::Entity> for Entity {
    /// into Converts an entity into a protobuf `common::api::Entity` representation.
    fn into(self) -> api::Entity {
        let mut e = api::Entity::new();
        e.set_id(self.id.to_vec());
        if self.eth_address.is_some() {
            e.set_eth_address(self.eth_address.unwrap().to_vec());
        }
        e
    }
}
