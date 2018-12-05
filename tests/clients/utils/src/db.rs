//! Read-only database access with best-effort freshness.

use std::sync::Arc;
use std::sync::Mutex;

use ekiden_core;
use ekiden_core::bytes::B256;
use ekiden_core::bytes::H256;
use ekiden_core::environment::Environment;
use ekiden_core::error::Result;
use ekiden_core::futures::prelude::*;
use ekiden_core::futures::streamfollow;
use ekiden_core::hash::empty_hash;
use ekiden_core::uint::U256;
use ekiden_db_trusted::patricia_trie::PatriciaTrie;
use ekiden_db_trusted::{Database, DatabaseHandle};
use ekiden_di::Container;
use ekiden_keymanager_common::StateKeyType;
use ekiden_roothash_base::{Block, RootHashBackend};
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

    fn set_root_hash(&mut self, _root_hash: H256) -> Result<()> {
        panic!("Can't set root hash for snapshot");
    }

    fn get_root_hash(&self) -> H256 {
        match self.root_hash {
            Some(root_hash) => root_hash,
            None => empty_hash(),
        }
    }

    fn commit(&mut self) -> Result<H256> {
        panic!("Can't commit Snapshot");
    }

    fn rollback(&mut self) {
        panic!("Can't rollback Snapshot")
    }

    fn with_encryption<F>(&mut self, _runtime_id: H256, _f: F)
    where
        F: FnOnce(&mut DatabaseHandle) -> (),
    {
        unimplemented!();
    }

    fn with_encryption_key<F>(&mut self, _key: StateKeyType, _f: F)
    where
        F: FnOnce(&mut DatabaseHandle) -> (),
    {
        unimplemented!();
    }
}

/// A holder of a (i) a root hash backend and (ii) a storage mapper, the two of which it uses to
/// create `Snapshot`s of recent (best-effort) states on demand.
pub struct Manager {
    /// Keep the environment alive.
    _env: Arc<Environment>,
    /// Keep the root hash backend alive.
    _roothash: Arc<RootHashBackend>,
    /// The latest root hash that we're aware of.
    root_hash: Arc<Mutex<Option<H256>>>,
    /// The storage mapper that we give to snapshots.
    mapper: Arc<StorageMapper>,
    /// For killing our root hash follower task.
    blocks_kill_handle: ekiden_core::futures::KillHandle,
}

impl Manager {
    pub fn new(
        env: Arc<Environment>,
        runtime_id: B256,
        roothash: Arc<RootHashBackend>,
        mapper: Arc<StorageMapper>,
    ) -> Self {
        let root_hash = Arc::new(Mutex::new(None));
        let root_hash_2 = root_hash.clone();
        let root_hash_init = roothash.clone();
        let root_hash_resume = roothash.clone();
        let (watch_blocks, blocks_kill_handle) = ekiden_core::futures::killable(
            streamfollow::follow(
                "db blocks",
                move || root_hash_init.get_blocks(runtime_id),
                move |round: &U256| root_hash_resume.get_blocks_since(runtime_id, round.clone()),
                |block: &Block| block.header.round,
                |_err| false,
            ).for_each(move |block: Block| {
                let mut guard = root_hash.lock().unwrap();
                *guard = Some(block.header.state_root);
                Ok(())
            }),
        );
        env.spawn(Box::new(watch_blocks.then(|r| {
            match r {
                // Block stream ended.
                Ok(Ok(())) => {
                    warn!("manager block stream ended");
                }
                // Manager dropped.
                Ok(Err(_ /* ekiden_core::futures::killable::Killed */)) => {}
                // Block stream errored.
                Err(e) => {
                    error!("manager block stream error: {}", e);
                }
            }
            Ok(())
        })));
        Self {
            _env: env,
            _roothash: roothash,
            root_hash: root_hash_2,
            mapper,
            blocks_kill_handle,
        }
    }

    /// Make a `Manager` from an injected `RootHashBackend` and an identity map over an injected
    /// `StorageBackend`.
    pub fn new_from_injected(runtime_id: B256, container: &mut Container) -> Result<Self> {
        let env: Arc<Environment> = container.inject()?;
        let roothash: Arc<RootHashBackend> = container.inject()?;
        let storage: Arc<StorageBackend> = container.inject()?;
        let mapper = Arc::new(BackendIdentityMapper::new(storage));
        Ok(Self::new(env, runtime_id, roothash, mapper))
    }

    pub fn get_snapshot(&self) -> Snapshot {
        Snapshot {
            root_hash: self.root_hash.lock().unwrap().clone(),
            trie: PatriciaTrie::new(self.mapper.clone()),
        }
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.blocks_kill_handle.kill();
    }
}

#[cfg(test)]
mod tests {
    use std;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    extern crate grpcio;

    use ekiden_core;
    use ekiden_core::bytes::B256;
    use ekiden_core::environment::GrpcEnvironment;
    use ekiden_core::futures::BoxFuture;
    use ekiden_core::futures::BoxStream;
    use ekiden_core::futures::Stream;
    use ekiden_core::uint::U256;
    use ekiden_db_trusted::patricia_trie::PatriciaTrie;
    use ekiden_db_trusted::Database;
    use ekiden_roothash_base::backend::Event;
    use ekiden_roothash_base::backend::RootHashBackend;
    use ekiden_roothash_base::block::Block;
    use ekiden_roothash_base::commitment::Commitment;
    use ekiden_roothash_base::header::Header;
    use ekiden_storage_base::mapper::BackendIdentityMapper;
    extern crate ekiden_storage_dummy;
    use self::ekiden_storage_dummy::DummyStorageBackend;

    /// A RootHashBackend that adapts a simple `Block` stream.
    struct MockRootHashBackend {
        blocks_rx: Mutex<Option<ekiden_core::futures::sync::mpsc::UnboundedReceiver<Block>>>,
    }

    impl RootHashBackend for MockRootHashBackend {
        fn get_blocks(&self, _runtime_id: B256) -> BoxStream<Block> {
            Box::new(
                self.blocks_rx
                    .lock()
                    .unwrap()
                    .take()
                    .expect("MockRootHashBackend only supports one block stream")
                    .map_err(|()| unimplemented!()),
            )
        }

        fn get_blocks_since(&self, _runtime_id: B256, _round: U256) -> BoxStream<Block> {
            unimplemented!()
        }

        fn get_events(&self, _runtime_id: B256) -> BoxStream<Event> {
            unimplemented!()
        }

        fn commit(&self, _runtime_id: B256, _commitment: Commitment) -> BoxFuture<()> {
            unimplemented!()
        }
    }

    #[test]
    fn play() {
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));
        let runtime_id = B256::from(*b"dummy runtime-------------------");
        let storage = Arc::new(DummyStorageBackend::new());
        let (blocks_tx, blocks_rx) = ekiden_core::futures::sync::mpsc::unbounded();
        let roothash = Arc::new(MockRootHashBackend {
            blocks_rx: Mutex::new(Some(blocks_rx)),
        });
        let mapper = Arc::new(BackendIdentityMapper::new(storage));
        let trie = PatriciaTrie::new(mapper.clone());
        let manager = super::Manager::new(environment, runtime_id, roothash, mapper);

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
