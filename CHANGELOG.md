# Unreleased

* **BACKWARD INCOMPATIBLE:** Store batches in storage and distribute only signed batch
  hashes to workers.
* **BACKWARD INCOMPATIBLE:** Remove `transactions` from consensus blocks and only store
  input/output hashes in block header. Content is delegated to storage.
* **BACKWARD INCOMPATIBLE:** Remove `submit` operation from consensus backend.
* **BACKWARD INCOMPATIBLE:** Compute node arguments `--dummy-host` and `--dummy-port`
  have been removed. Backend-specific configuration arguments should be used instead.
* Add discrepancy resolution by using backup workers majority vote.
* Add passing extra arguments to Docker in shell (`--docker-extra-args`).
* Add `common::futures::retry` which implements retrying futures on failure.
* Add support for dependency injection.
* Bugfix: `epochtime::LocalTimeSourceNotifier::watch_epochs()` will now
  correctly broadcast the current epoch if it is available.
* The initial Ethereum smart contract based Random Beacon has been added.

# 0.1.0

* **BACKWARD INCOMPATIBLE:** Remove old consensus node.
* **BACKWARD INCOMPATIBLE:** Compute node now requires the shared dummy node.
* gRPC message types and conversion convention established.
* Registry interface / centralized implementation added. (For entities and contracts)
* Epoch interface / implementation added.
* Random beacon interface / unsafe implementation added.
* Make contract client sharable between threads.
* Use new consensus interface in the compute node.
* Add common `StreamSubscribers<T>` structure for easier handling of various subscriptions
  to streams of items.
* Bugfix: Release script updates shell environment.
* Scheduler interface / centralized implementation added.
* Use new storage interface in the compute node.
* Bugfix: AVR timestamp parsing should now be correct.
* Add `common::epochtime::TimeSourceNotifier` to enable event driven epoch time.
* Add `common::epochtime::MockTimeSource` to simplify testing.
* Extend `beacon::base::RandomBeacon` to enable event driven beacons.
* Extend `scheduler::base::Scheduler` to enable event driven scheduling.
* Add `common::futures::GrpcExecutor`.
* Leader now forwards batches to workers in compute replica group.
* Add `into_box`, `log_errors_and_discard` to `FutureExt` trait and `for_each_log_errors`
  to StreamExt trait to simplify stream processing.
* Clients using `client-utils` now automatically discover the compute replica group leader.
* Change consensus interface to support multiple contracts.
* Use Merkle Patricia tree for state storage.
* Dockerfile includes truffle for solidity development.
* Add LRU cache storage backend that can wrap any existing storage backend to add an
  in-memory cache.
* RPCs can be configured to time out, treating compute nodes that
  don't respond in time as failing. To enable timeouts, pass
  `--rpc-timeout SECONDS` in clients that use client-utils and
  `--forwarded-rpc-timeout SECONDS` in ekiden-compute.
* EntityRegistry support for per-epoch node lists.  `get_nodes()` now takes an
  epoch, and a `watch_node_list()` routine to subscribe to node list generation
  has been added.

# 0.1.0-alpha.4

* **BACKWARD INCOMPATIBLE:** All RPC calls are now stateless with no access to storage. Only
  the new async contract calls are stateful.
* **BACKWARD INCOMPATIBLE:** The RPC client and backend structures have been renamed from
  `ContractClient*` to `RpcClient*` (the `ContractClient*` prefix is now used for the async
  contract interface).
* **BACKWARD INCOMPATIBLE:** Replace `Serializable`/`Deserializable` traits with Serde's
  `Serialize`/`Deserialize`.
* **BACKWARD INCOMPATIBLE:** Use full public key instead of just its hash in `Signature`.
* Add async contract interface in addition to RPC interface.
