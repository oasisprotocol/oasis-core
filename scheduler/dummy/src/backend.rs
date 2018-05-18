//! Ekiden dummy scheduler backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_beacon_base::RandomBeacon;
use ekiden_common::contract::Contract;
use ekiden_common::drbg::HmacDrbgRng;
use ekiden_common::epochtime::{EpochTime, TimeSourceNotifier, EKIDEN_EPOCH_INVALID};
use ekiden_common::futures::{future, BoxFuture, BoxStream, Executor, Future, Stream};
use ekiden_core::bytes::B256;
use ekiden_core::error::{Error, Result};
use ekiden_core::node::Node;
use ekiden_core::subscribers::StreamSubscribers;
use ekiden_registry_base::{ContractRegistryBackend, EntityRegistryBackend};
use ekiden_scheduler_base::*;

#[cfg(not(target_env = "sgx"))]
use rand::Rng;
#[cfg(target_env = "sgx")]
use sgx_rand::Rng;

const RNG_CONTEXT_COMPUTE: &'static [u8] = b"EkS-Dummy-Compute";
const RNG_CONTEXT_STORAGE: &'static [u8] = b"EkS-Dummy-Storage";

enum AsyncEvent {
    Beacon((EpochTime, B256)),
    Contract(Contract),
    Epoch(EpochTime),
}

struct DummySchedulerBackendInner {
    beacon: Arc<RandomBeacon>,
    contract_registry: Arc<ContractRegistryBackend>,
    entity_registry: Arc<EntityRegistryBackend>,
    time_notifier: Arc<TimeSourceNotifier>,

    subscribers: StreamSubscribers<Committee>,

    beacon_cache: HashMap<EpochTime, B256>,
    entity_cache: HashMap<EpochTime, Vec<Node>>,
    contract_cache: HashMap<B256, Arc<Contract>>,
    committee_cache: HashMap<EpochTime, HashMap<B256, Vec<Committee>>>,
    current_epoch: EpochTime,
}

impl DummySchedulerBackendInner {
    fn new(
        beacon: Arc<RandomBeacon>,
        contract_registry: Arc<ContractRegistryBackend>,
        entity_registry: Arc<EntityRegistryBackend>,
        time_notifier: Arc<TimeSourceNotifier>,
    ) -> Self {
        Self {
            beacon: beacon,
            contract_registry: contract_registry,
            entity_registry: entity_registry,
            time_notifier: time_notifier,
            subscribers: StreamSubscribers::new(),
            beacon_cache: HashMap::new(),
            entity_cache: HashMap::new(),
            contract_cache: HashMap::new(),
            committee_cache: HashMap::new(),
            current_epoch: EKIDEN_EPOCH_INVALID,
        }
    }

    fn on_random_beacon(&mut self, epoch: EpochTime, beacon: B256) {
        // Cache the beacon value.
        let cached = self.beacon_cache.entry(epoch).or_insert(beacon);
        assert_eq!(*cached, beacon, "Beacon changed for epoch: {}", epoch);
    }

    fn on_epoch_transition(&mut self, epoch: EpochTime) {
        // Cache the epoch.
        self.current_epoch = epoch;

        // Get the epoch's node list.
        //
        // TODO: While this *should* be event driven, every scheduler
        // instance on potentially different nodes must have a consistent
        // node list on a per-election basis.  This serves to push that
        // requirement down to the entity registry, where it belongs.
        //
        // So yes, this uses wait() for now.  The correct thing to do is
        // for the registry to provide a stream of (EpochTime, Vec<Node>)
        // on a per-epoch basis.
        assert!(
            !self.entity_cache.contains_key(&epoch),
            "Node list already present for epoch: {}",
            epoch
        );
        let mut nodes = self.entity_registry.get_nodes().wait().unwrap();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));

        self.entity_cache.insert(epoch, nodes);
    }

    fn on_contract(&mut self, contract: Contract) {
        // Add the contract to the cache.
        let contract_id = contract.id;
        match self.contract_cache.get(&contract_id) {
            Some(cached) => {
                // Tolerate duplicate Contract notifications, assuming
                // the contents do not change.
                assert_eq!(
                    **cached, contract,
                    "Contract entry changed: {:?}",
                    contract_id
                );
            }
            None => {}
        };

        let contract = Arc::new(contract);
        self.contract_cache.insert(contract_id, contract.clone());

        // Elect the contract's comittees if possible.
        if !self.can_elect() {
            return;
        }
        match self.do_election(contract) {
            Ok(()) => {}
            Err(err) => {
                warn!(
                    "Failed to elect committees for contract {:?}: {}",
                    contract_id, err
                );
            }
        }
    }

    fn do_election(&mut self, contract: Arc<Contract>) -> Result<()> {
        let contract_id = contract.id;

        let committee_cache = self.committee_cache
            .entry(self.current_epoch)
            .or_insert(HashMap::new());
        if committee_cache.contains_key(&contract_id) {
            return Err(Error::new(
                "Committee cache already contains comittees for epoch",
            ));
        }

        // Elect.
        let epoch = self.current_epoch;
        let entropy = self.beacon_cache.get(&epoch).unwrap();
        let nodes = self.entity_cache.get(&epoch).unwrap();
        let compute = make_committee_impl(
            contract.clone(),
            &nodes,
            CommitteeType::Compute,
            &entropy,
            epoch,
        )?;
        let storage =
            make_committee_impl(contract, &nodes, CommitteeType::Storage, &entropy, epoch)?;
        committee_cache.insert(contract_id, vec![compute.clone(), storage.clone()]);

        // Notify.
        self.subscribers.notify(&compute);
        self.subscribers.notify(&storage);

        Ok(())
    }

    fn maybe_mass_elect(&mut self) {
        // The "maybe", is conditional enough internal state being available.
        if !self.can_elect() {
            return;
        }

        // Mass elect the new committees.
        let contracts: Vec<_> = self.contract_cache
            .values()
            .map(|contract| contract.clone())
            .collect();
        for contract in contracts {
            let contract_id = contract.id;
            match self.do_election(contract) {
                Ok(()) => {}
                Err(err) => {
                    warn!(
                        "Failed to elect committees for contract {:?}: {}",
                        contract_id, err
                    );
                }
            }
        }

        let current_epoch = self.current_epoch;

        // Prune stale state.
        self.beacon_cache.retain(|epoch, _| epoch >= &current_epoch);
        self.entity_cache.retain(|epoch, _| epoch >= &current_epoch);
        self.committee_cache
            .retain(|epoch, _| epoch >= &current_epoch);
    }

    fn can_elect(&self) -> bool {
        let epoch = self.current_epoch;

        // Ensure that the view of the world is current and complete.
        self.beacon_cache.contains_key(&epoch) && self.entity_cache.contains_key(&epoch)
    }

    fn get_committees(&self, contract_id: B256, epoch: EpochTime) -> BoxFuture<Vec<Committee>> {
        // Attempt to service this from the internal cache.
        match self.committee_cache.get(&epoch) {
            Some(committees) => {
                match committees.get(&contract_id) {
                    Some(committees) => return Box::new(future::ok(committees.clone())),
                    None => {}
                };
            }
            None => {}
        };

        // Do this the hard way by querying the beacon/entity registry.
        //
        // TODO: This may be better off either returning an error, or
        // returning a future that queries the caches when the information
        // is available, or just flat out failing.
        let get_metadata = {
            // TODO: entity_registry.get_nodes() should probably take an
            // EpochTime since this absolutely depends on a stable/globally
            // consistent node list.
            self.beacon.get_beacon(epoch).join3(
                self.entity_registry.get_nodes(),
                self.contract_registry.get_contract(contract_id),
            )
        };
        let result = get_metadata.and_then(move |(entropy, nodes, contract)| {
            let contract = Arc::new(contract);
            let compute = match make_committee_impl(
                contract.clone(),
                &nodes,
                CommitteeType::Compute,
                &entropy,
                epoch,
            ) {
                Ok(v) => v,
                Err(err) => return Box::new(future::err(err)),
            };

            let storage = match make_committee_impl(
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

/// A dummy scheduler backend.
///
/// **This backend should only be used for tests.***
pub struct DummySchedulerBackend {
    inner: Arc<Mutex<DummySchedulerBackendInner>>,
}

impl DummySchedulerBackend {
    /// Create a new dummy scheduler.
    pub fn new(
        beacon: Arc<RandomBeacon>,
        contract_registry: Arc<ContractRegistryBackend>,
        entity_registry: Arc<EntityRegistryBackend>,
        time_notifier: Arc<TimeSourceNotifier>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DummySchedulerBackendInner::new(
                beacon,
                contract_registry,
                entity_registry,
                time_notifier,
            ))),
        }
    }
}

impl Scheduler for DummySchedulerBackend {
    fn start(&self, executor: &mut Executor) {
        // Subscribe to all event sources.
        //
        // Note: This assumes that every event source will send the current
        // state (if any) on subscription.
        //
        // BUG: None of the registries actually implement the on-subscription
        // semantics required to catch up.
        executor.spawn({
            let shared_inner = self.inner.clone();
            let inner = self.inner.lock().unwrap();

            // TODO: Subscribe to the entity registry, once it can present
            // globally consistent, per-epoch views of the world.
            let beacon_stream = inner.beacon.watch_beacons().map(AsyncEvent::Beacon);
            let contract_stream = inner
                .contract_registry
                .get_contracts()
                .map(AsyncEvent::Contract);
            let epoch_stream = inner.time_notifier.watch_epochs().map(AsyncEvent::Epoch);

            // TODO: futures_util has stream::SelectAll, which appears to be
            // a less awful way of doing this.
            let event_stream = beacon_stream.select(contract_stream).select(epoch_stream);

            Box::new(
                event_stream
                    .for_each(move |event| {
                        let mut inner = shared_inner.lock().unwrap();
                        match event {
                            AsyncEvent::Beacon((epoch, beacon)) => {
                                inner.on_random_beacon(epoch, beacon);
                                inner.maybe_mass_elect();
                            }
                            AsyncEvent::Contract(contract) => inner.on_contract(contract),
                            AsyncEvent::Epoch(epoch) => {
                                inner.on_epoch_transition(epoch);
                                inner.maybe_mass_elect();
                            }
                        };
                        Ok(())
                    })
                    .then(|_| future::ok(())),
            )
        })
    }

    fn get_committees(&self, contract_id: B256) -> BoxFuture<Vec<Committee>> {
        let inner = self.inner.lock().unwrap();

        let epoch = match inner.time_notifier.time_source().get_epoch() {
            Ok((epoch, _)) => epoch,
            Err(err) => return Box::new(future::err(err)),
        };

        inner.get_committees(contract_id, epoch)
    }

    fn watch_committees(&self) -> BoxStream<Committee> {
        let inner = self.inner.lock().unwrap();
        let (send, recv) = inner.subscribers.subscribe();

        // Feed every single currently valid committee, to catch up the
        // subscriber to current time.
        if inner.current_epoch != EKIDEN_EPOCH_INVALID {
            let committees = match inner.committee_cache.get(&inner.current_epoch) {
                Some(committees) => committees,
                None => {
                    return recv;
                }
            };
            for contract_committees in committees.values() {
                for committee in contract_committees {
                    send.unbounded_send(committee.clone()).unwrap();
                }
            }
        }

        recv
    }
}

fn make_committee_impl(
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

#[cfg(test)]
mod tests {
    extern crate ekiden_beacon_dummy;
    extern crate ekiden_registry_base;
    extern crate ekiden_registry_dummy;
    extern crate serde_cbor;

    use self::ekiden_beacon_dummy::InsecureDummyRandomBeacon;
    use self::ekiden_registry_base::REGISTER_CONTRACT_SIGNATURE_CONTEXT;
    use self::ekiden_registry_base::test::populate_entity_registry;
    use self::ekiden_registry_dummy::{DummyContractRegistryBackend, DummyEntityRegistryBackend};
    use self::serde_cbor::to_vec;
    use super::*;
    use ekiden_common::bytes::B256;
    use ekiden_common::contract::Contract;
    use ekiden_common::epochtime::{MockTimeSource, TimeSourceNotifier, EPOCH_INTERVAL};
    use ekiden_common::futures::cpupool;
    use ekiden_common::ring::signature::Ed25519KeyPair;
    use ekiden_common::signature::{InMemorySigner, Signature, Signed};
    use ekiden_common::untrusted;
    use std::collections::HashSet;

    #[test]
    fn test_dummy_scheduler_integration() {
        let time_source = Arc::new(MockTimeSource::new());
        let time_notifier = Arc::new(TimeSourceNotifier::new(time_source.clone()));
        let beacon = Arc::new(InsecureDummyRandomBeacon::new(time_notifier.clone()));
        let contract_registry = Arc::new(DummyContractRegistryBackend::new());
        let entity_registry = Arc::new(DummyEntityRegistryBackend::new());
        let scheduler = DummySchedulerBackend::new(
            beacon.clone(),
            contract_registry.clone(),
            entity_registry.clone(),
            time_notifier.clone(),
        );

        let mut pool = cpupool::CpuPool::new(1);
        beacon.start(&mut pool);
        scheduler.start(&mut pool);

        // Populate the entity registry.
        let mut nodes = vec![];
        for _ in 0..10 {
            nodes.push(B256::random());
        }
        populate_entity_registry(entity_registry.clone(), nodes.clone());
        let nodes: HashSet<B256> = nodes.iter().cloned().collect();

        // Fake contract.
        let contract_sk =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let contract = Contract {
            id: B256::from(contract_sk.public_key_bytes()),
            store_id: B256::random(),
            code: vec![],
            minimum_bond: 0,
            mode_nondeterministic: false,
            features_sgx: false,
            advertisement_rate: 0,
            replica_group_size: 3,
            storage_group_size: 5,
        };
        let contract_signer = InMemorySigner::new(contract_sk);
        let contract_sig = Signature::sign(
            &contract_signer,
            &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
            &to_vec(&contract).unwrap(),
        );
        let signed_contract = Signed::from_parts(contract.clone(), contract_sig);
        contract_registry
            .register_contract(signed_contract)
            .wait()
            .unwrap();
        let contract = Arc::new(contract);

        // Test single scheduling a contract (slow path, cache miss).
        //
        // WARNING: If the inner get_committees() routine ever changes
        // to return a future that waits on the notifications internally
        // this will hang indefinately.
        let committees = scheduler
            .get_committees(contract.id.clone())
            .wait()
            .unwrap();
        must_validate_committees(contract.clone(), &nodes, committees, 0);

        // Subscribe to the scheduler.
        let get_committees = scheduler.watch_committees().take(2).collect();

        // Pump the time source.
        time_source.set_mock_time(0, EPOCH_INTERVAL).unwrap();
        time_notifier.notify_subscribers().unwrap();

        // Consume all the notifications.
        let committees = get_committees.wait().unwrap();
        must_validate_committees(contract.clone(), &nodes, committees, 0);

        // Test single scheduling a contract (cache hit).
        let committees = scheduler
            .get_committees(contract.id.clone())
            .wait()
            .unwrap();
        must_validate_committees(contract.clone(), &nodes, committees, 0);
    }

    fn must_validate_committees(
        contract: Arc<Contract>,
        nodes: &HashSet<B256>,
        committees: Vec<Committee>,
        now: EpochTime,
    ) {
        // Validate committee sanity.
        let mut has_compute = false;
        let mut has_storage = false;
        for com in committees {
            // Ensure that the committee is for the correct contract and epoch.
            assert_eq!(com.contract, contract);
            assert_eq!(com.valid_for, now);

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
