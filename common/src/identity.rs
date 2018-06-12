//! Local node/entity identity.
use std::sync::Arc;

use super::bytes::{B256, B64};
use super::entity::Entity;
use super::node::Node;
use super::signature::{Signed, Signer};
use super::x509;

/// Node identity.
///
/// The local identity contains descriptors and key pairs for the node.
pub trait NodeIdentity: Sync + Send {
    /// Return descriptor for the local node.
    fn get_node(&self) -> Node;

    /// Return signer for the local node.
    fn get_node_signer(&self) -> Arc<Signer>;

    /// Return public key for the node identity.
    fn get_public_key(&self) -> B256 {
        self.get_node_signer().get_public_key()
    }

    /// Return certificate used for TLS connections.
    fn get_tls_certificate(&self) -> &x509::Certificate;

    /// Return private key used for TLS connections.
    fn get_tls_private_key(&self) -> &x509::PrivateKey;
}

/// Entity identity.
///
/// The local identity contains descriptors and key pairs for the entity.
pub trait EntityIdentity: Sync + Send {
    /// Return descriptor for the local entity.
    fn get_entity(&self) -> Entity;

    /// Return signer for the local entity.
    fn get_entity_signer(&self) -> Arc<Signer>;

    /// Returned signed node descriptor (e.g., for registration).
    fn get_signed_entity(&self, context: &B64) -> Signed<Entity> {
        Signed::sign(&self.get_entity_signer(), context, self.get_entity())
    }

    /// Return public key for the entity identity.
    fn get_public_key(&self) -> B256 {
        self.get_entity_signer().get_public_key()
    }
}
