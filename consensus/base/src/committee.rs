//! Committee node type.
use ekiden_common::bytes::B256;
use ekiden_common::signature::PublicKeyVerifier;

/// Committee node role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Worker node.
    Worker,
    /// Group leader.
    Leader,
}

/// Committee node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeNode {
    /// Node role.
    pub role: Role,
    /// Node public key.
    pub public_key: B256,
}

impl CommitteeNode {
    /// Return signature verifier for this node.
    pub fn get_verifier<'a>(&'a self) -> PublicKeyVerifier<'a> {
        PublicKeyVerifier::new(&self.public_key)
    }
}
