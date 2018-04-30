//! Entity Interface.
use std::convert::TryFrom;

use bytes::B256;
use error::Error;

use ekiden_common_api as api;

/// Entity. An entity controls one or multiple Nodes / services.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// The public key identifying this Entity.
    pub id: B256,
}

impl TryFrom<api::Entity> for Entity {
    /// try_from Converts a protobuf `common::api::Entity` into an Entity.
    type Error = super::error::Error;
    fn try_from(a: api::Entity) -> Result<Self, Error> {
        let id = a.get_id();
        let id = B256::from_slice(&id);

        Ok(Entity { id: id })
    }
}

impl Into<api::Entity> for Entity {
    /// into Converts an entity into a protobuf `common::api::Entity` representation.
    fn into(self) -> api::Entity {
        let mut e = api::Entity::new();
        e.set_id(self.id.to_vec());
        e
    }
}
