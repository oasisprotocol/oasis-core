//! Scheduler interface.
use std::convert::TryFrom;

use serde::{self, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use ekiden_common::{bytes::B256, error::Error, futures::BoxFuture};
use ekiden_scheduler_api as api;

/// The role a given Node plays in a committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Invalid role (should never appear on the wire).
    Invalid = 0,
    /// Worker node.
    Worker,
    /// Backup worker node for discrepancy resolution.
    BackupWorker,
    /// Group leader.
    Leader,
}

impl Serialize for Role {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = match u8::deserialize(deserializer)? {
            1 => Role::Worker,
            2 => Role::BackupWorker,
            3 => Role::Leader,
            _ => return Err(serde::de::Error::custom("invalid role")),
        };

        Ok(value)
    }
}

/// A node participating in a committee.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CommitteeNode {
    /// Node role.
    pub role: Role,
    /// Node public key.
    pub public_key: B256,
}

// NOTE: We need to implement a custom Serialize because we need canonical encoding,
//       e.g., fields sorted by name.
impl Serialize for CommitteeNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut node = serializer.serialize_struct("CommitteeNode", 2)?;
        node.serialize_field("public_key", &self.public_key)?;
        node.serialize_field("role", &self.role)?;
        node.end()
    }
}

impl TryFrom<api::CommitteeNode> for CommitteeNode {
    /// try_from Converts a protobuf block into a block.
    type Error = Error;
    fn try_from(a: api::CommitteeNode) -> Result<Self, self::Error> {
        Ok(CommitteeNode {
            role: match a.get_role() {
                api::CommitteeNode_Role::WORKER => Role::Worker,
                api::CommitteeNode_Role::BACKUP_WORKER => Role::BackupWorker,
                api::CommitteeNode_Role::LEADER => Role::Leader,
                _ => return Err(Error::new("invalid role")),
            },
            public_key: B256::from(a.get_public_key()),
        })
    }
}

impl Into<api::CommitteeNode> for CommitteeNode {
    /// into Converts a block into a protobuf `consensus::api::Block` representation.
    fn into(self) -> api::CommitteeNode {
        let mut c = api::CommitteeNode::new();
        match self.role {
            Role::Worker => c.set_role(api::CommitteeNode_Role::WORKER),
            Role::BackupWorker => c.set_role(api::CommitteeNode_Role::BACKUP_WORKER),
            Role::Leader => c.set_role(api::CommitteeNode_Role::LEADER),
            _ => panic!("invalid role"),
        };
        c.set_public_key(self.public_key.to_vec());
        c
    }
}

/// The functionality a committee exists to provide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommitteeType {
    Compute = 0,
    Storage,
}

impl Serialize for CommitteeType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for CommitteeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = match u8::deserialize(deserializer)? {
            0 => CommitteeType::Compute,
            1 => CommitteeType::Storage,
            _ => return Err(serde::de::Error::custom("invalid committee type")),
        };

        Ok(value)
    }
}

/// A per-runtime (per-runtime instance) committee instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committee {
    pub kind: CommitteeType,
    pub members: Vec<CommitteeNode>,
    // We can recreate the runtime from other data we have, so the runtime
    // ID is not really needed here.
    #[serde(skip)]
    pub runtime_id: B256,
    pub valid_for: u64,
}

impl TryFrom<api::Committee> for Committee {
    /// try_from Converts a protobuf block into a block.
    type Error = Error;
    fn try_from(a: api::Committee) -> Result<Self, self::Error> {
        let mut members = Vec::new();
        for member in a.get_members().iter() {
            members.push(CommitteeNode::try_from(member.to_owned())?);
        }
        let rid = a.get_runtime_id();
        let rid = B256::from_slice(&rid);
        Ok(Committee {
            kind: match a.get_kind() {
                api::Committee_Kind::COMPUTE => CommitteeType::Compute,
                api::Committee_Kind::STORAGE => CommitteeType::Storage,
            },
            members: members,
            runtime_id: rid,
            valid_for: a.get_valid_for(),
        })
    }
}

impl Into<api::Committee> for Committee {
    /// into Converts a block into a protobuf `consensus::api::Block` representation.
    fn into(self) -> api::Committee {
        let mut c = api::Committee::new();
        match self.kind {
            CommitteeType::Compute => c.set_kind(api::Committee_Kind::COMPUTE),
            CommitteeType::Storage => c.set_kind(api::Committee_Kind::STORAGE),
        };
        let mut members = Vec::new();
        for member in self.members.iter() {
            members.push(member.to_owned().into());
        }
        c.set_members(members.into());
        c.set_runtime_id(self.runtime_id.to_vec());
        c.set_valid_for(self.valid_for);
        c
    }
}

/// Scheduler backend implementing the Ekiden scheduler interface.
pub trait Scheduler: Send + Sync {
    /// Return a vector of the committees for a given runtime ID,
    /// for the current epoch.
    fn get_committees(&self, runtime: B256) -> BoxFuture<Vec<Committee>>;
}
