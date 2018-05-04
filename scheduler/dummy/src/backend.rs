//! Ekiden dummy scheduler backend.
use std::sync::Arc;

use ekiden_beacon_base::RandomBeacon;
use ekiden_common::contract::Contract;
use ekiden_common::drbg::HmacDrbgRng;
use ekiden_common::epochtime::{EpochTime, TimeSource};
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_core::error::{Error, Result};
use ekiden_core::node::Node;
use ekiden_registry_base::RegistryBackend;
use ekiden_scheduler_base::*;

#[cfg(not(target_env = "sgx"))]
use rand::Rng;
#[cfg(target_env = "sgx")]
use sgx_rand::Rng;

const RNG_CONTEXT_COMPUTE: &'static [u8] = b"EkS-Dummy-Compute";
const RNG_CONTEXT_STORAGE: &'static [u8] = b"EkS-Dummy-Storage";

struct DummySchedulerBackendInner {
    beacon: Arc<RandomBeacon>,
    registry: Arc<RegistryBackend>,
    time_source: Arc<TimeSource>,
}

impl DummySchedulerBackendInner {
    fn make_committee(
        &self,
        contract: Arc<Contract>,
        nodes: &Vec<Node>,
        kind: CommitteeType,
        entropy: &[u8],
        epoch: EpochTime,
    ) -> Result<Committee> {
        let (ctx, size) = match kind {
            CommitteeType::Compute => (RNG_CONTEXT_COMPUTE, contract.replica_group_size as usize),
            CommitteeType::Storage => (RNG_CONTEXT_STORAGE, contract.storage_group_size as usize),
        };
        if size == 0 {
            return Err(Error::new("Empty committee not allowed"));
        }
        if size > nodes.len() {
            return Err(Error::new("Committee size exceeds available nodes"));
        }

        // Initialize the RNG.
        let mut ps = Vec::with_capacity(contract.id.len() + ctx.len());
        ps.extend_from_slice(&contract.id); // NIST puts the nonce first.
        ps.extend_from_slice(ctx);
        let mut rng = HmacDrbgRng::new(entropy, &ps)?;

        // Select the committee.  A real implementation will do something
        // more sophisticated here, such as weighting the nodes by stake,
        // excluding candidates that do not meet the appropriate criteria,
        // and load balancing.
        let mut candidates = nodes.to_owned();
        rng.shuffle(&mut candidates);

        let mut members = Vec::with_capacity(size);
        for i in 0..size {
            let role = match i {
                0 => Role::Leader,
                _ => Role::Worker,
            };
            members.push(CommitteeNode {
                role: role,
                public_key: candidates[i].id,
            });
        }

        Ok(Committee {
            kind: kind,
            contract: contract,
            members: members,
            valid_for: epoch,
        })
    }
}

/// A dummy scheduler backend.
///
/// **This backend should only be used for tests.***
pub struct DummySchedulerBackend {
    inner: Arc<DummySchedulerBackendInner>,
}

impl DummySchedulerBackend {
    pub fn new(
        beacon: Arc<RandomBeacon>,
        registry: Arc<RegistryBackend>,
        time_source: Arc<TimeSource>,
    ) -> Self {
        Self {
            inner: Arc::new(DummySchedulerBackendInner {
                beacon: beacon,
                registry: registry,
                time_source: time_source,
            }),
        }
    }
}

impl Scheduler for DummySchedulerBackend {
    fn get_committees(&self, contract: Arc<Contract>) -> BoxFuture<Vec<Committee>> {
        // Use a single consistent epoch/beacon for the whole call.
        let epoch = match self.inner.time_source.get_epoch() {
            Ok((epoch, _)) => epoch,
            Err(err) => return Box::new(future::err(err)),
        };

        let shared_inner = self.inner.clone();
        let get_metadata = {
            shared_inner
                .beacon
                .get_beacon(epoch)
                .join(shared_inner.registry.get_nodes())
        };
        let result = get_metadata.and_then(move |(entropy, nodes)| {
            let compute_contract = contract.clone();
            let compute = match shared_inner.make_committee(
                compute_contract,
                &nodes,
                CommitteeType::Compute,
                &entropy,
                epoch,
            ) {
                Ok(v) => v,
                Err(err) => return Box::new(future::err(err)),
            };

            let storage = match shared_inner.make_committee(
                contract,
                &nodes,
                CommitteeType::Storage,
                &entropy,
                epoch,
            ) {
                Ok(v) => v,
                Err(err) => return Box::new(future::err(err)),
            };

            Box::new(future::ok(vec![compute, storage]))
        });
        Box::new(result)
    }
}

#[cfg(test)]
mod tests {
    extern crate ekiden_beacon_dummy;
    extern crate ekiden_registry_base;
    extern crate ekiden_registry_dummy;
    extern crate serde_cbor;

    use self::ekiden_beacon_dummy::InsecureDummyRandomBeacon;
    use self::ekiden_registry_base::{REGISTER_ENTITY_SIGNATURE_CONTEXT,
                                     REGISTER_NODE_SIGNATURE_CONTEXT};
    use self::ekiden_registry_dummy::DummyRegistryBackend;
    use self::serde_cbor::to_vec;
    use super::*;
    use ekiden_common::bytes::B256;
    use ekiden_common::contract::Contract;
    use ekiden_common::entity::Entity;
    use ekiden_common::epochtime::SystemTimeSource;
    use ekiden_common::node::Node;
    use ekiden_common::ring::signature::Ed25519KeyPair;
    use ekiden_common::signature::{InMemorySigner, Signature, Signed};
    use ekiden_common::untrusted;
    use std::collections::HashSet;

    #[test]
    fn test_dummy_scheduler_integration() {
        let beacon = Arc::new(InsecureDummyRandomBeacon {});
        let registry = Arc::new(DummyRegistryBackend::new());
        let time_source = Arc::new(SystemTimeSource {});
        let scheduler =
            DummySchedulerBackend::new(beacon.clone(), registry.clone(), time_source.clone());

        // Fake entity.
        let entity_sk =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let entity_pk = B256::from(entity_sk.public_key_bytes());
        let entity = Entity { id: entity_pk };
        let entity_signer = InMemorySigner::new(entity_sk);
        let entity_sig = Signature::sign(
            &entity_signer,
            &REGISTER_ENTITY_SIGNATURE_CONTEXT,
            &to_vec(&entity).unwrap(),
        );
        let signed_entity = Signed::from_parts(entity, entity_sig);
        registry.register_entity(signed_entity).wait().unwrap();

        // Fake nodes.
        let mut nodes = HashSet::new();
        for _ in 0..10 {
            let node = Node {
                id: B256::random(),
                entity_id: entity_pk,
                expiration: 0xffffffffffffffff,
                addresses: vec![],
                stake: vec![],
            };
            nodes.insert(node.id);
            let node_sig = Signature::sign(
                &entity_signer,
                &REGISTER_NODE_SIGNATURE_CONTEXT,
                &to_vec(&node).unwrap(),
            );
            let signed_node = Signed::from_parts(node, node_sig);
            registry.register_node(signed_node).wait().unwrap();
        }

        // Fake contract.
        let contract = Contract {
            id: B256::random(),
            store_id: B256::random(),
            code: vec![],
            minimum_bond: 0,
            mode_nondeterministic: false,
            features_sgx: false,
            advertisement_rate: 0,
            replica_group_size: 3,
            storage_group_size: 5,
        };
        let contract = Arc::new(contract);

        // Schedule the contract.
        let (now, _) = time_source.get_epoch().unwrap();
        let committees = scheduler.get_committees(contract.clone()).wait().unwrap();

        // Validate committee sanity.
        let mut has_compute = false;
        let mut has_storage = false;
        for com in committees {
            // Ensure that the committee is for the correct contract and epoch.
            assert_eq!(com.contract, contract);
            assert_eq!(com.valid_for, now); // May race.

            // Ensure that only 1 of each committee is returned, and that the
            // expected number of nodes are present.
            match com.kind {
                CommitteeType::Compute => {
                    assert_eq!(has_compute, false);
                    assert_eq!(com.members.len() as u64, contract.replica_group_size);
                    has_compute = true;
                }
                CommitteeType::Storage => {
                    assert_eq!(has_storage, false);
                    assert_eq!(com.members.len() as u64, contract.storage_group_size);
                    has_storage = true;
                }
            }

            // Ensure that only 1 Leader is returned, and that each member is
            // unique, and actually a node.
            let mut com_nodes = HashSet::new();
            let mut has_leader = false;
            for node in com.members {
                match node.role {
                    Role::Leader => {
                        assert_eq!(has_leader, false);
                        has_leader = true;
                    }
                    _ => {}
                }
                assert!(!com_nodes.contains(&node.public_key));
                com_nodes.insert(node.public_key.clone());
            }
            assert!(com_nodes.is_subset(&nodes));
            assert!(has_leader);
        }
        assert!(has_compute);
        assert!(has_storage);
    }
}
