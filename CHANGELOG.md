# Unreleased

* gRPC message types and conversion convention established.
* Registry interface / centralized implementation added.
* Make contract client sharable between threads.
* Use new consensus interface in the compute node.

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
