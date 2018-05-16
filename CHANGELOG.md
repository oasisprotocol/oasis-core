# Unreleased

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
