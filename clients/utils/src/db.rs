//! Read-only database access with best-effort freshness.

use std::sync::Arc;
use std::sync::Mutex;

use futures;
use futures::future::Either;
use futures::Future;
use futures::Stream;
use tokio;

use ekiden_common::bytes::B256;
use ekiden_common::bytes::H256;
use ekiden_common::error::Result;
use ekiden_consensus_base::ConsensusBackend;
use ekiden_db_trusted::patricia_trie::PatriciaTrie;
use ekiden_db_trusted::Database;
use ekiden_di::Container;
use ekiden_storage_base::BackendIdentityMapper;
use ekiden_storage_base::StorageBackend;
use ekiden_storage_base::StorageMapper;

/// An implementation of the read methods of `Database`. Represents a single fixed state.
pub struct Snapshot {
    root_hash: Option<H256>,
    trie: PatriciaTrie,
}

impl Database for Snapshot {
    fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.trie.get(self.root_hash, key)
    }

    fn insert(&mut self, _key: &[u8], _value: &[u8]) -> Option<Vec<u8>> {
        panic!("Can't insert into Snapshot")
    }

    fn remove(&mut self, _key: &[u8]) -> Option<Vec<u8>> {
        panic!("Can't remove from Snapshot")
    }

    fn clear(&mut self) {
        panic!("Can't clear Snapshot")
    }
}

/// A holder of a (i) a consensus backend and (ii) a storage mapper, the two of which it uses to
/// create `Snapshot`s of recent (best-effort) states on demand.
pub struct Manager {
    root_hash: Arc<Mutex<Option<H256>>>,
    mapper: Arc<StorageMapper>,
    _drop_tx: futures::sync::oneshot::Sender<()>,
}

impl Manager {
    pub fn new(
        contract_id: B256,
        consensus: &ConsensusBackend,
        mapper: Arc<StorageMapper>,
    ) -> Self {
        let root_hash = Arc::new(Mutex::new(None));
        let (drop_tx, drop_rx) = futures::sync::oneshot::channel();
        let manager = Self {
            root_hash: root_hash.clone(),
            mapper,
            _drop_tx: drop_tx,
        };
        tokio::spawn(
            consensus
                .get_blocks(contract_id)
                .for_each(move |block| {
                    let mut guard = root_hash.lock().unwrap();
                    *guard = Some(block.header.state_root);
                    Ok(())
                })
                .select2(drop_rx)
                .then(|r| {
                    match r {
                        // Block stream ended.
                        Ok(Either::A(((), _))) => {
                            warn!("manager block stream ended");
                        }
                        // Drop channel resolved.
                        Ok(Either::B(((), _))) => unreachable!(),
                        // Block stream errored.
                        Err(Either::A((e, _))) => {
                            error!("manager block stream error: {}", e);
                        }
                        // Drop channel canceled.
                        Err(Either::B((futures::Canceled, _))) => {}
                    }
                    Ok(())
                }),
        );
        manager
    }

    /// Make a `Manager` from an injected `ConsensusBackend` and an identity map over an injected
    /// `StorageBackend`.
    pub fn new_from_injected(contract_id: B256, container: &mut Container) -> Result<Self> {
        let consensus: Arc<ConsensusBackend> = container.inject()?;
        let storage: Arc<StorageBackend> = container.inject()?;
        let mapper = Arc::new(BackendIdentityMapper::new(storage));
        Ok(Self::new(contract_id, consensus.as_ref(), mapper))
    }

    pub fn get_snapshot(&self) -> Snapshot {
        Snapshot {
            root_hash: self.root_hash.lock().unwrap().clone(),
            trie: PatriciaTrie::new(self.mapper.clone()),
        }
    }
}
