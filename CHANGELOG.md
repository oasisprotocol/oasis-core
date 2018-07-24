# Unreleased

* **BACKWARD INCOMPATIBLE:** Store batches in storage and distribute only signed batch
  hashes to workers.
* **BACKWARD INCOMPATIBLE:** Remove `transactions` from consensus blocks and only store
  input/output hashes in block header. Content is delegated to storage.
* **BACKWARD INCOMPATIBLE:** Remove `submit` operation from consensus backend.
* **BACKWARD INCOMPATIBLE:** Compute node arguments `--dummy-host` and `--dummy-port`
  have been removed. Backend-specific configuration arguments should be used instead.
* **BACKWARD INCOMPATIBLE:** The Ethereum backend(s), Rust glue, and build
  tooling have all been moved to a single `ethereum/` crate.
* **BACKWARD INCOMPATIBLE:** Dummy node now requires `--storage-backend BACKEND` option.
  Use backend `dummy` for original behavior.
* **BACKWARD INCOMPATIBLE:** Bump `protobuf` dependency to `2.0`.
* **BACKWARD INCOMPATIBLE:** Remove unused key manager support from compute node.
* **BACKWARD INCOMPATIBLE:** Use TLS for compute node gRPC channels.
* **BACKWARD INCOMPATIBLE:** Separate node/entity key pair arguments and change serialized
  node key pair format in a backward-incompatible way.
* **BACKWARD INCOMPATIBLE:** Make commitment and reveal message format consensus backend
  dependent and introduce `ConsensusSigner` interface to generate them.
* **BACKWARD INCOMPATIBLE:** Compute node now requires `--batch-storage IMPL` option. Use
  `--batch-storage immediate_remote` for original behavior.
* **BACKWARD INCOMPATIBLE:** Use TLS client authentication for gRPC channels, encode
  node Ed25519 public key in TLS certificates, remove custom signed RPC arguments.
* **BACKWARD INCOMPATIBLE:** Rename `build-contract` to `build-enclave`.
* **BACKWARD INCOMPATIBLE:** Rename consensus backend to root hash backend to make it more
  clear what its role is.
* **BACKWARD INCOMPATIBLE:** Move local node identity implementations to `ekiden-common`
  (previously they were part of `ekiden-ethereum`).
* **BACKWARD INCOMPATIBLE:** Make raw contract calls unsigned as signatures and encryption
  should be handled by the runtime.
* Add discrepancy resolution by using backup workers majority vote.
* Add passing extra arguments to Docker in shell (`--docker-extra-args`).
* Add `common::futures::retry` which implements retrying futures on failure.
* Add support for dependency injection.
* Bugfix: `epochtime::LocalTimeSourceNotifier::watch_epochs()` will now
  correctly broadcast the current epoch if it is available.
* The initial Ethereum smart contract based Random Beacon has been added.
* Add `common::testing::try_init_logging` which can be called from tests to
  initialize logging while honoring `cargo test`'s capture behavior.
* Move `GrpcEnvironment` to `common::environment` to make it reusable.
* Add `spawn` to `common::environment::Environment` to make it easier to spawn tasks
  using the environment's default executor.
* Make clients aware of compute committee changes and manage connections.
* Added AWS DynamoDB-backed storage backend.
* Backport `SelectAll` stream combinator from futures 0.3.
* Add generic instrumentation framework (`ekiden-instrumentation`) and a Prometheus
  frontend (`ekiden-instrumentation-prometheus`).
* Added the multilayer storage backend described in RFC 0004.
* You can now configure the last resort layer in the multilayer storage backend.
* Handle stragglers in dummy consensus backend.
* Change async contract call submission protocol to avoid the use of enclave RPC.

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
