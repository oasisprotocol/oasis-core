use std::sync::Mutex;

use oasis_core_runtime::{common::crypto::signature, future::block_on};

use crate::client::{KeyManagerClient, RemoteClient};

use super::SecretProvider;

struct Inner {
    client: RemoteClient,
    nodes: Vec<signature::PublicKey>,
    last_node: usize,
}

/// Key manager secret provider facilitates access to master and ephemeral secrets retrieved
/// from remote key manager enclaves.
pub struct KeyManagerSecretProvider {
    inner: Mutex<Inner>,
}

impl KeyManagerSecretProvider {
    /// Create a new key manager secret provider.
    pub fn new(client: RemoteClient, nodes: Vec<signature::PublicKey>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                client,
                nodes,
                last_node: 0,
            }),
        }
    }
}

impl SecretProvider for KeyManagerSecretProvider {
    fn master_secret_iter(
        &self,
        generation: u64,
    ) -> Box<dyn Iterator<Item = crate::crypto::VerifiableSecret> + '_> {
        // Start fetching secrets from the last connected node.
        let start = { self.inner.lock().unwrap().last_node };
        let mut counter = 0;

        // Iterate over all nodes, ignoring errors.
        Box::new(std::iter::from_fn(move || {
            let mut inner = self.inner.lock().unwrap();
            let total = inner.nodes.len();

            while counter < total {
                let idx = (start + counter) % total;
                inner.last_node = idx;
                counter += 1;

                if let Ok(secret) = block_on(
                    inner
                        .client
                        .replicate_master_secret(generation, vec![inner.nodes[idx]]),
                ) {
                    return Some(secret);
                }
            }

            None
        }))
    }

    fn ephemeral_secret_iter(
        &self,
        epoch: oasis_core_runtime::consensus::beacon::EpochTime,
    ) -> Box<dyn Iterator<Item = crate::crypto::Secret> + '_> {
        // Start fetching secrets from the last connected node.
        let start = { self.inner.lock().unwrap().last_node };
        let mut counter = 0;

        // Iterate over all nodes, ignoring errors.
        Box::new(std::iter::from_fn(move || {
            let mut inner = self.inner.lock().unwrap();
            let total = inner.nodes.len();

            while counter < total {
                let idx = (start + counter) % total;
                inner.last_node = idx;
                counter += 1;

                if let Ok(secret) = block_on(
                    inner
                        .client
                        .replicate_ephemeral_secret(epoch, vec![inner.nodes[idx]]),
                ) {
                    return Some(secret);
                }
            }

            None
        }))
    }
}
