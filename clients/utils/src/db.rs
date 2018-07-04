//! Read-only database access with best-effort freshness.

use std::sync::Arc;
use std::sync::Mutex;

use futures;
use futures::future::Either;
use futures::Future;
use futures::Stream;

use ekiden_common::bytes::B256;
use ekiden_common::bytes::H256;
use ekiden_common::environment::Environment;
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
    /// The root hash that identifies the state in this snapshot.
    root_hash: Option<H256>,
    /// This handles access to the database and holds on to the storage mapper reference.
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
    /// The latest root hash that we're aware of.
    root_hash: Arc<Mutex<Option<H256>>>,
    /// The storage mapper that we give to snapshots.
    mapper: Arc<StorageMapper>,
    /// This kills our consensus follower task when when we drop the manager.
    _drop_tx: futures::sync::oneshot::Sender<()>,
}

impl Manager {
    pub fn new(
        env: &Environment,
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
        env.spawn(Box::new(
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
        ));
        manager
    }

    /// Make a `Manager` from an injected `ConsensusBackend` and an identity map over an injected
    /// `StorageBackend`.
    pub fn new_from_injected(contract_id: B256, container: &mut Container) -> Result<Self> {
        let env: Arc<Environment> = container.inject()?;
        let consensus: Arc<ConsensusBackend> = container.inject()?;
        let storage: Arc<StorageBackend> = container.inject()?;
        let mapper = Arc::new(BackendIdentityMapper::new(storage));
        Ok(Self::new(
            env.as_ref(),
            contract_id,
            consensus.as_ref(),
            mapper,
        ))
    }

    pub fn get_snapshot(&self) -> Snapshot {
        Snapshot {
            root_hash: self.root_hash.lock().unwrap().clone(),
            trie: PatriciaTrie::new(self.mapper.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use futures;
    use futures::Stream;
    extern crate grpcio;

    use ekiden_common::bytes::B256;
    use ekiden_common::environment::GrpcEnvironment;
    use ekiden_common::futures::BoxFuture;
    use ekiden_common::futures::BoxStream;
    use ekiden_consensus_base::backend::ConsensusBackend;
    use ekiden_consensus_base::backend::Event;
    use ekiden_consensus_base::block::Block;
    use ekiden_consensus_base::commitment::Commitment;
    use ekiden_consensus_base::commitment::Reveal;
    use ekiden_consensus_base::header::Header;
    use ekiden_db_trusted::patricia_trie::PatriciaTrie;
    use ekiden_db_trusted::Database;
    use ekiden_storage_base::mapper::BackendIdentityMapper;
    extern crate ekiden_storage_dummy;
    use self::ekiden_storage_dummy::DummyStorageBackend;

    /// A ConsensusBackend that adapts a simple `Block` stream.
    struct MockConsensus {
        blocks_rx: Mutex<Option<futures::sync::mpsc::UnboundedReceiver<Block>>>,
    }

    impl ConsensusBackend for MockConsensus {
        fn get_blocks(&self, _contract_id: B256) -> BoxStream<Block> {
            Box::new(
                self.blocks_rx
                    .lock()
                    .unwrap()
                    .take()
                    .expect("MockConsensus only supports one block stream")
                    .map_err(|()| unimplemented!()),
            )
        }

        fn get_events(&self, _contract_id: B256) -> BoxStream<Event> {
            unimplemented!()
        }

        fn commit(&self, _contract_id: B256, _commitment: Commitment) -> BoxFuture<()> {
            unimplemented!()
        }

        fn reveal(&self, _contract_id: B256, _reveal: Reveal) -> BoxFuture<()> {
            unimplemented!()
        }

        fn commit_many(&self, _contract_id: B256, _commitments: Vec<Commitment>) -> BoxFuture<()> {
            unimplemented!()
        }

        fn reveal_many(&self, _contract_id: B256, _reveals: Vec<Reveal>) -> BoxFuture<()> {
            unimplemented!()
        }
    }

    #[test]
    fn play() {
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));
        let contract_id = B256::from(*b"dummy contract------------------");
        let storage = Arc::new(DummyStorageBackend::new());
        let (blocks_tx, blocks_rx) = futures::sync::mpsc::unbounded();
        let consensus = Arc::new(MockConsensus {
            blocks_rx: Mutex::new(Some(blocks_rx)),
        });
        let mapper = Arc::new(BackendIdentityMapper::new(storage));
        let trie = PatriciaTrie::new(mapper.clone());
        let manager = super::Manager::new(
            environment.as_ref(),
            contract_id,
            consensus.as_ref(),
            mapper,
        );

        let root_hash_before = trie.insert(None, b"changeme", b"before");
        blocks_tx
            .unbounded_send(Block {
                header: Header {
                    state_root: root_hash_before,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        // Give the manager some time to pickup the new block.
        std::thread::sleep(Duration::from_millis(1000));

        // Check that a snapshot can read data.
        let snapshot_before = manager.get_snapshot();
        assert_eq!(&snapshot_before.get(b"changeme").unwrap(), b"before");

        let root_hash_after = trie.insert(Some(root_hash_before), b"changeme", b"after");
        blocks_tx
            .unbounded_send(Block {
                header: Header {
                    state_root: root_hash_after,
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        std::thread::sleep(Duration::from_millis(1000));

        // Check that a new snapshot has new data.
        let snapshot_after = manager.get_snapshot();
        assert_eq!(&snapshot_after.get(b"changeme").unwrap(), b"after");

        // Check that the old snapshot is still consistent.
        assert_eq!(&snapshot_before.get(b"changeme").unwrap(), b"before");
    }
}
