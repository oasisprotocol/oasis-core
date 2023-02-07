# Change Log

All notables changes to this project are documented in this file.

The format is inspired by [Keep a Changelog].

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/

<!-- markdownlint-disable no-duplicate-heading -->

<!-- NOTE: towncrier will not alter content above the TOWNCRIER line below. -->

<!-- TOWNCRIER -->

## 22.2.6 (2023-02-06)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Bug Fixes

- go/worker/compute: Do not drop valid proposals
  ([#5161](https://github.com/oasisprotocol/oasis-core/issues/5161))

  Previously valid proposals could be dropped instead of being forwarded
  via the P2P gossip when the local node's consensus view was slightly
  behind even though the proposal was valid. With smaller committees and
  certain topologies this could result in some nodes not getting the
  proposals.

## 22.2.5 (2023-01-21)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Bug Fixes

- ci: Use Ubuntu 20.04 for release builds
  ([#5130](https://github.com/oasisprotocol/oasis-core/issues/5130))

  This was automatically changed when `ubuntu-latest` was switched to
  Ubuntu 22.04. We should use the same build environment for all of the patch
  releases (22.2.4 is an exception as we didn't see this earlier).

- runtime: Clear verification trace after block verification
  ([#5148](https://github.com/oasisprotocol/oasis-core/issues/5148))

### Internal Changes

- runtime/src/protocol: Remove consensus version compatibility check
  ([#5135](https://github.com/oasisprotocol/oasis-core/issues/5135))

  Consensus version check was a sanity check which didn't allow dump-restore
  upgrades. The removal did no harm as the consensus version was never
  authenticated and light clients use the verifier to check state compatibility
  and authenticity.

- runtime/src/consensus/registry: Add runtime encryption key (REK)
  ([#5137](https://github.com/oasisprotocol/oasis-core/issues/5137))

  Added REK to the node TEE capability descriptor to ensure old enclaves won't
  panic when new ones register with a non-nil REK.

- runtime: Attempt to flush buffers before aborting
  ([#5146](https://github.com/oasisprotocol/oasis-core/issues/5146))

- runtime: Simplify the LRU-backed consensus verifier light store
  ([#5149](https://github.com/oasisprotocol/oasis-core/issues/5149))

## 22.2.4 (2023-01-11)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Bug Fixes

- go/runtime/registry: Fix watching policy updates
  ([#5092](https://github.com/oasisprotocol/oasis-core/issues/5092))

  When multiple key managers were running, the last known status of the
  runtime's key manager was overwritten with each status update. On runtime
  (re)starts, this resulted in the wrong policy being set.

- go/worker/client: Better handle latest round queries with verification
  ([#5123](https://github.com/oasisprotocol/oasis-core/issues/5123))

  When a query is requesting to be executed against the latest round and
  the runtime reports a consensus verifier error, use an earlier round
  instead as the latest round may not yet be verifiable by the light
  client as it needs to wait for the validator signatures.

### Internal Changes

- runtime/src/protocol: Deserialize unknown rhp messages as invalid
  ([#5094](https://github.com/oasisprotocol/oasis-core/issues/5094))

  Runtime-host protocol terminated the reader thread when failed to deserialize
  a runtime message on the Rust side (e.g. when `Body` enum contained an unknown
  field). Decoding is now more robust as these messages are deserialized as
  invalid and latter discarded and logged as malformed by the handler.

- rust: Bump tokio from 1.21.2 to 1.24.1
  ([#5120](https://github.com/oasisprotocol/oasis-core/issues/5120))

## 22.2.3 (2022-11-23)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Bug Fixes

- runtime/consensus/tendermint/verifier: Correctly compare headers
  ([#5068](https://github.com/oasisprotocol/oasis-core/issues/5068))

  Since the store may have an earlier (non-canonical, but valid) version
  of the block available, we need to only compare the actual header and
  not the commits/signatures.

  This is because it can happen that during the immediate sync the light
  block does not yet contain all of the commits (but only just enough to
  be valid, e.g. 2/3+) and this gets stored in the light block store.
  Later on (e.g. during a query) the presented light block may have the
  full set of commits.

## 22.2.2 (2022-11-17)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Features

- registry: Add MaxRuntimeDeployments parameter
  ([#5049](https://github.com/oasisprotocol/oasis-core/issues/5049))

### Bug Fixes

- keymanager: Fix replication backwards compatibility
  ([#5044](https://github.com/oasisprotocol/oasis-core/issues/5044))

- runtime: Properly handle state root verification on backup nodes
  ([#5053](https://github.com/oasisprotocol/oasis-core/issues/5053))

### Internal Changes

- go: Ignore CVE-2022-44797 until tendermint uses newer btcd
  ([#5024](https://github.com/oasisprotocol/oasis-core/issues/5024))

- runtime: Bump oasis-cbor to 0.5.1
  ([#5035](https://github.com/oasisprotocol/oasis-core/issues/5035))

## 22.2.1 (2022-11-05)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Features

- go/consensus/tendermint/apps/staking: Reduce DelegationsTo scanning
  ([#5011](https://github.com/oasisprotocol/oasis-core/issues/5011))

### Bug Fixes

- go/runtime/txpool: republish sooner if republish limit is reached
  ([#5003](https://github.com/oasisprotocol/oasis-core/issues/5003))

  This fixes a case where a part of a batch of transaction would take a long
  time to be published in case there are no new transactions being submitted.

- go/worker/common: Reorder state determination checks
  ([#5005](https://github.com/oasisprotocol/oasis-core/issues/5005))

  Otherwise the shown state would be misleading, e.g. showing that it is
  waiting for runtime host being provisioned while it is actually blocked
  in initialization like storage sync.

- go/p2p/rpc: Fix multi call dispatch to different peers
  ([#5005](https://github.com/oasisprotocol/oasis-core/issues/5005))

- go/storage/mkvs/checkpoint: Exclude initial version when pruning
  ([#5005](https://github.com/oasisprotocol/oasis-core/issues/5005))

- go/worker/storage: Fix case when checkpoint sync disabled but forced
  ([#5005](https://github.com/oasisprotocol/oasis-core/issues/5005))

  If checkpoint sync is disabled but sync has been forced (e.g. because
  the state at genesis is non-empty), we must request to sync the
  checkpoint at genesis as otherwise we will jump to a later state which
  may not be desired given that checkpoint sync has been explicitly
  disabled via config.

- go/p2p/rpc: Fix peer grading when context is canceled
  ([#5007](https://github.com/oasisprotocol/oasis-core/issues/5007))

  When method `CallMulti` finishes early, the requests in progress are canceled
  and unfairly recorded as failed.

- go/p2p/rpc: Fix memory leak when RPC multi call finishes early
  ([#5007](https://github.com/oasisprotocol/oasis-core/issues/5007))

  When method `CallMulti` finishes early, the result channel is never cleared.
  Therefore, the channel never closes and leaves one go routine hanging.

- go/common/workerpool: Fix memory leak when workerpool is stopped early
  ([#5008](https://github.com/oasisprotocol/oasis-core/issues/5008))

  When workerpool si stopped, the job channel might still contain jobs which
  haven't been processed. Therefore, the channel never closes and leaves one
  go routine hanging.

## 22.2 (2022-10-13)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.1.0     |
| Runtime Committee | 4.0.0     |

### Removals and Breaking Changes

- go/staking/grpc: rename misnamed GovernanceDeposits method
  ([#4652](https://github.com/oasisprotocol/oasis-core/issues/4652))

- go/runtime: Mandate the use of runtime schedule control
  ([#4665](https://github.com/oasisprotocol/oasis-core/issues/4665))

  Runtimes that do not support the schedule control feature will no longer work
  with executor nodes.

### Features

- Add support for PCS attestation
  ([#4806](https://github.com/oasisprotocol/oasis-core/issues/4806),
   [#4789](https://github.com/oasisprotocol/oasis-core/issues/4789),
   [#4720](https://github.com/oasisprotocol/oasis-core/issues/4720),
   [#4752](https://github.com/oasisprotocol/oasis-core/issues/4752))

- go/governance: Add change parameters proposal
  ([#4938](https://github.com/oasisprotocol/oasis-core/issues/4938))

  Introducing a new governance proposal for changing consensus parameters.
  Until now, this was possible only with an upgrade governance proposal
  which was not very efficient.

- Add archive mode support
  ([#4539](https://github.com/oasisprotocol/oasis-core/issues/4539))

  Node started in archive mode only serves existing consensus and runtime
  states. The node has all unneeded consensus and P2P functionality disabled so
  it wont participate in the network. Archive mode can be set using the
  `consensus.tendermint.mode` setting.

- go/control: Show the debug option statuses in the control output
  ([#4634](https://github.com/oasisprotocol/oasis-core/issues/4634))

- runtime: Make persistent transaction check state configurable
  ([#4640](https://github.com/oasisprotocol/oasis-core/issues/4640))

- go/runtime/txpool: Limit outstanding transactions per sender
  ([#4665](https://github.com/oasisprotocol/oasis-core/issues/4665))

- go/control/status: Add fields for quick overview of node status
  ([#4669](https://github.com/oasisprotocol/oasis-core/issues/4669))

- go/worker/storage: Make checkpoint sync peer selection smarter
  ([#4671](https://github.com/oasisprotocol/oasis-core/issues/4671))

- runtime: verify epoch in dispatcher using consensus verifier
  ([#4677](https://github.com/oasisprotocol/oasis-core/issues/4677))

- go/worker/compute: Ensure trust root is verified before registering
  ([#4678](https://github.com/oasisprotocol/oasis-core/issues/4678))

- go/worker/compute: Start batch resolution early for backup worker
  ([#4679](https://github.com/oasisprotocol/oasis-core/issues/4679))

- go/runtime/txpool: Add roothash incoming messages' data as transactions
  ([#4681](https://github.com/oasisprotocol/oasis-core/issues/4681))

  Roothash incoming messages can provide a piece of data for the runtime.
  With this change, the data is now treated as a transaction.

  Along with this change, we're splitting the txpool into multiple queues.
  The transactions collected from roothash incoming messages go in a special
  queue that does not undergo checking or broadcasting.

  We also make another queue for a node's own transactions, so that a proposer
  can prioritize its own transactions.

- go/worker/registration: add node status metrics
  ([#4686](https://github.com/oasisprotocol/oasis-core/issues/4686))

- runtime: Enable dispatcher to verify state integrity for queries
  ([#4694](https://github.com/oasisprotocol/oasis-core/issues/4694),
   [#4830](https://github.com/oasisprotocol/oasis-core/issues/4830),
   [#4904](https://github.com/oasisprotocol/oasis-core/issues/4904))

- go/worker/common/p2p: Add support for persistent and blocked peers
  ([#4713](https://github.com/oasisprotocol/oasis-core/issues/4713))

- go/worker/common: Properly handle dynamic key manager configuration
  ([#4715](https://github.com/oasisprotocol/oasis-core/issues/4715))

  Since the runtime can go from having no key manager configured to having one,
  the worker node should handle this correctly.

- go/runtime/txpool: Add txpool metric for rejected runtime transactions
  ([#4724](https://github.com/oasisprotocol/oasis-core/issues/4724))

- runtime: Verify RAK in consensus state when serving requests
  ([#4741](https://github.com/oasisprotocol/oasis-core/issues/4741))

- runtime: Add support for reporting EnclaveRPC peer feedback
  ([#4757](https://github.com/oasisprotocol/oasis-core/issues/4757))

  This makes EnclaveRPC more robust as the higher-level layer in the
  runtime can trigger peer replacement on high level errors.

- archive-mode: disable runtime P2P if archive mode is used
  ([#4775](https://github.com/oasisprotocol/oasis-core/issues/4775))

- go/consensus/tendermint: Add `consensus.tendermint.halt_height`
  ([#4793](https://github.com/oasisprotocol/oasis-core/issues/4793))

  This is equivalent to the cosmos `halt-height` option, to be used to
  bring a node down gracefully at a specific height.

- net-runner: Add --fixture.default.runtime.version flag
  ([#4813](https://github.com/oasisprotocol/oasis-core/issues/4813))

- go/oasis-node: allow km to have private peers
  ([#4821](https://github.com/oasisprotocol/oasis-core/issues/4821))

- go/runtime/registry: allow client nodes to run sgx runtimes
  ([#4832](https://github.com/oasisprotocol/oasis-core/issues/4832))

  Client nodes can now run runtimes in SGX, which enables them to execute
  signed queries if peered with a keymanager.

- go/worker/keymanager: Add key manager worker metrics
  ([#4877](https://github.com/oasisprotocol/oasis-core/issues/4877))

  The following metrics were added:

  - oasis_worker_keymanager_compute_runtime_count

  - oasis_worker_keymanager_enclave_rpc_count

  - oasis_worker_keymanager_policy_update_count

- go/control/status: Add key manager worker status to node status
  ([#4883](https://github.com/oasisprotocol/oasis-core/issues/4883))

- keymanager: Add support for ephemeral keys
  ([#4888](https://github.com/oasisprotocol/oasis-core/issues/4888))

- oasis-net-runner: Set default max_allowances, increase test account balance
  ([#4902](https://github.com/oasisprotocol/oasis-core/issues/4902))

  The max_allowances staking setting in the default oasis-net-runner fixture has
  been changed from 0 to 16 matching the testnet and mainnet setting. This
  enables the allowance transactions locally which are required for doing
  deposits to runtimes.

  The initial balance of the default test account generated by the
  oasis-net-runner was increased from 100 tokens to 1 million. This makes the
  account directly suitable for deploying and running confidential smart
  contracts (e.g. on the local Cipher instance) with more realistic transaction
  fees.

- runtime/consensus/verifier: Support trust root consensus layer upgrades
  ([#4903](https://github.com/oasisprotocol/oasis-core/issues/4903))

- runtime: Support consensus event queries
  ([#4904](https://github.com/oasisprotocol/oasis-core/issues/4904))

- keymanager: Validate latest trust root height in key manager requests
  ([#4910](https://github.com/oasisprotocol/oasis-core/issues/4910))

- registry: Add ProveFreshness consensus layer transaction
  ([#4916](https://github.com/oasisprotocol/oasis-core/issues/4916))

  Introducing new transaction that accepts a fixed-size binary blob of 32 bytes
  and always succeeds without doing any processing or state changes. Transaction
  is needed for client node TEE freshness verification and enabled via
  freshness_proofs parameter located in tee_features consensus parameter group.

- runtime: Add client node TEE freshness verification
  ([#4922](https://github.com/oasisprotocol/oasis-core/issues/4922))

- keymanager: Verify that policy was published in the consensus layer
  ([#4925](https://github.com/oasisprotocol/oasis-core/issues/4925))

- Bind TEE attestations to nodes and enforce freshness
  ([#4926](https://github.com/oasisprotocol/oasis-core/issues/4926))

- go/genesis: Cache computed genesis document hash
  ([#4919](https://github.com/oasisprotocol/oasis-core/issues/4919))

- go/oasis-node/cmd: unsafe-reset preserve local storage by default
  ([#4700](https://github.com/oasisprotocol/oasis-core/issues/4700))

- go/oasis-node/cmd: unsafe-reset check datadir validity
  ([#4702](https://github.com/oasisprotocol/oasis-core/issues/4702))

- runtime: Emit runtime logs as oasis-node logs
  ([#4709](https://github.com/oasisprotocol/oasis-core/issues/4709),
   [#4924](https://github.com/oasisprotocol/oasis-core/issues/4924))

  Previously, runtime logs used a slightly different format.
  Also, they were written to stdout in a manner that was not
  synchronized with node logs, so the two sets of logs
  sometimes intertwined mid-line. Those annoyances are gone,
  plus runtime logs are now annotated with the runtime ID.

### Bug Fixes

- go/worker/compute: Always include resolved transactions
  ([#4633](https://github.com/oasisprotocol/oasis-core/issues/4633))

- go/runtime/txpool: Fix crash on early access
  ([#4638](https://github.com/oasisprotocol/oasis-core/issues/4638))

- go/worker/compute: Improve proposed transaction handling
  ([#4640](https://github.com/oasisprotocol/oasis-core/issues/4640))

- go/runtime/host: Always emit StoppedEvent on stop
  ([#4647](https://github.com/oasisprotocol/oasis-core/issues/4647))

  Previously the StoppedEvent was only emitted in case the runtime was
  previously running. In case multihost was performing a version switch when a
  runtime was not yet started, this resulted in a deadlock.

- go/worker/common/p2p: Make sure P2P stops before service cleanup runs
  ([#4650](https://github.com/oasisprotocol/oasis-core/issues/4650))

  Otherwise this may result in a crash during shutdown when P2P requests are
  processed while database is already closed.

- go/oasis-node/cmd/control: Fix runtime-stats arg
  ([#4659](https://github.com/oasisprotocol/oasis-core/issues/4659))

- Fix waiting for deregister event on `RequestShutdown`
  ([#4662](https://github.com/oasisprotocol/oasis-core/issues/4662))

- go/worker/compute: Only advertise active version for TEE runtimes
  ([#4683](https://github.com/oasisprotocol/oasis-core/issues/4683))

  Previously this caused additional downtime on upgrades due to capability
  updates not being allowed.

- go/runtime/host/sandbox: Properly handle clone3 in seccomp policy
  ([#4687](https://github.com/oasisprotocol/oasis-core/issues/4687),
   [#4861](https://github.com/oasisprotocol/oasis-core/issues/4861),
   [#4867](https://github.com/oasisprotocol/oasis-core/issues/4867))

  We need to handle the clone3 syscall in a special manner as there are
  several complications to its handling:

  - Newer glibc versions will try clone3 first and if they see EPERM they
    will instantly fail making the program unable to spawn threads.

  - The clone3 syscall is much more complex than clone and so we can't
    simply inspect its flags as we do for clone.

  Therefore we need to reject the syscall with ENOSYS, causing fallback to
  clone.

- go/runtime/config: report error if SGX loader required but not configured
  ([#4710](https://github.com/oasisprotocol/oasis-core/issues/4710))

- go/worker/keymanager: Fix crash on capability TEE updates
  ([#4725](https://github.com/oasisprotocol/oasis-core/issues/4725))

- go/worker/registration: Only register once epoch is known
  ([#4726](https://github.com/oasisprotocol/oasis-core/issues/4726))

- go/runtime/registry: Refresh key manager policy on runtime changes
  ([#4729](https://github.com/oasisprotocol/oasis-core/issues/4729))

  Since the runtime can change dynamically (due to version upgrades), we
  need to make sure that we notify the new runtime as well.

- go/runtime/config: fix SGX provisioner check for runtimes without SGX
  ([#4734](https://github.com/oasisprotocol/oasis-core/issues/4734))

  This fixes a bug in `22.1.5` where an SGX provisioner was required even for
  non-SGX runtimes.

- runtime/common/version: fix from u64 conversion
  ([#4741](https://github.com/oasisprotocol/oasis-core/issues/4741))

- go/common/quantity: Avoid side-effects on errors
  ([#4790](https://github.com/oasisprotocol/oasis-core/issues/4790))

- net-runner: Fix regression introduced in #4564
  ([#4808](https://github.com/oasisprotocol/oasis-core/issues/4808))

  Fix the missing Deployments field when oasis-net-runner generating the genesis
  state and no key manager is provided.

- go/registry/api/runtime: ensure no nil deployments in ValidateDeployments
  ([#4822](https://github.com/oasisprotocol/oasis-core/issues/4822))

- go/registry/api: ensure no nil runtimes in VerifyRegisterNodeArgs
  ([#4822](https://github.com/oasisprotocol/oasis-core/issues/4822))

- go/consensus/tendermint: Make sure DBs are only closed during cleanup
  ([#4823](https://github.com/oasisprotocol/oasis-core/issues/4823))

- go/oasis-node/cmd/genesis: Fix reading of height argument when dumping state
  ([#4892](https://github.com/oasisprotocol/oasis-core/issues/4892))

  Command line argument for block height was mistakenly read from an invalid
  source, which caused all state dumps to be made at height 0 (the most recent
  block height).

- go/runtime/txpool: Add block propagation delay before tx publish
  ([#4959](https://github.com/oasisprotocol/oasis-core/issues/4959))

- go/runtime: Fix configuring the SGX-based provisioner
  ([#4960](https://github.com/oasisprotocol/oasis-core/issues/4960))

  Previously there was an edge case when the SGX loader was configured and
  remapping to non-SGX was forced (e.g. on client nodes). This would result in
  an invalid SGX configuration that resulted in a strange error message about a
  missing SIGSTRUCT.

  This has now been changed so that remapping happens independent of whether an
  SGX loader is configured or not.

- go/worker/compute: Only process keymanager client initialization once
  ([#4962](https://github.com/oasisprotocol/oasis-core/issues/4962))

### Documentation Improvements

- Document `gcc-multilib` dependency for Ubuntu/Debian systems
  ([#4475](https://github.com/oasisprotocol/oasis-core/issues/4475))

  It is needed for building `oasis-core-runtime`.

- doc: Replace community slack links with discord
  ([#4751](https://github.com/oasisprotocol/oasis-core/issues/4751))

- doc: Migrate ADRs to oasisprotocol/adrs repo
  ([#4770](https://github.com/oasisprotocol/oasis-core/issues/4770))

### Internal Changes

- oasis-net-runner: support configuring runtime state and state root
  ([#4843](https://github.com/oasisprotocol/oasis-core/issues/4843))

- go/worker/common/p2p/rpc: Add support for per-call peer limits
  ([#4671](https://github.com/oasisprotocol/oasis-core/issues/4671))

- docker: Add oasisprotocol/aesmd Docker image
  ([#4690](https://github.com/oasisprotocol/oasis-core/issues/4690))

- runtime: Bump tendermint-rs, x509-parser and oid-registry
  ([#4706](https://github.com/oasisprotocol/oasis-core/issues/4706))

- ci: Build OpenSSL statically for Oasis Core releases
  ([#4707](https://github.com/oasisprotocol/oasis-core/issues/4707))

  This makes sure that oasis-core-loader is more portable between
  distributions.

- go/common/sgx/aesm: Add support for newer methods
  ([#4711](https://github.com/oasisprotocol/oasis-core/issues/4711))

- rust-toolchain: Migrate to TOML version of rust-toolchain
  ([#4727](https://github.com/oasisprotocol/oasis-core/issues/4727))

- go/common/node/address: use custom type instead of `net.TCPAddr`
  ([#4744](https://github.com/oasisprotocol/oasis-core/issues/4744))

- go: Bump go-libp2p to 0.23.2
  ([#4765](https://github.com/oasisprotocol/oasis-core/issues/4765),
   [#4782](https://github.com/oasisprotocol/oasis-core/issues/4782),
   [#4906](https://github.com/oasisprotocol/oasis-core/issues/4906),
   [#4944](https://github.com/oasisprotocol/oasis-core/issues/4944))

- go: Bump viper to 1.12.0
  ([#4766](https://github.com/oasisprotocol/oasis-core/issues/4766))

- go/oasis-test-runner/fixture: support configuring runtime messages
  ([#4769](https://github.com/oasisprotocol/oasis-core/issues/4769))

- runtime: Bump oasis-cbor to 0.5.0
  ([#4784](https://github.com/oasisprotocol/oasis-core/issues/4784),
   [#4835](https://github.com/oasisprotocol/oasis-core/issues/4835))

- go/oasis-test-runner/byzantine: Add primary+backup liveness test
  ([#4799](https://github.com/oasisprotocol/oasis-core/issues/4799))

- Bump Go to 1.18.3
  ([#4820](https://github.com/oasisprotocol/oasis-core/issues/4820))

- go/runtime/host: Make sure runtime-reported version matches bundle
  ([#4825](https://github.com/oasisprotocol/oasis-core/issues/4825))

- go: remove synced storage wrapper
  ([#4837](https://github.com/oasisprotocol/oasis-core/issues/4837))

- go/common/sgx/sigstruct: Add support for offline signing
  ([#4844](https://github.com/oasisprotocol/oasis-core/issues/4844))

- go: Drop go-fuzz in favor of Go 1.18 fuzzing support
  ([#4875](https://github.com/oasisprotocol/oasis-core/issues/4875))

- keymanager-client: Skip policy when OASIS_UNSAFE_SKIP_KM_POLICY is set
  ([#4878](https://github.com/oasisprotocol/oasis-core/issues/4878))

- go/common/grpc: advancedtls options moved to IdentityOptions
  ([#4886](https://github.com/oasisprotocol/oasis-core/issues/4886))

- runtime: Refactor dispatcher initializer and expose consensus_verifier
  ([#4893](https://github.com/oasisprotocol/oasis-core/issues/4893))

- runtime: Add state_at to consensus Verifier trait
  ([#4893](https://github.com/oasisprotocol/oasis-core/issues/4893))

  This allows fetching historic consensus layer state in addition to the
  latest state.

- Bump Rust toolchain to 2022-08-22
  ([#4896](https://github.com/oasisprotocol/oasis-core/issues/4896))

- runtime: Add epoch_state query and EPOCH_INVALID constant
  ([#4897](https://github.com/oasisprotocol/oasis-core/issues/4897))

- go: Bump Tendermint to v0.34.21
  ([#4899](https://github.com/oasisprotocol/oasis-core/issues/4899))

- go: Add consensus transaction prioritization
  ([#4911](https://github.com/oasisprotocol/oasis-core/issues/4911))

- go/worker/keymanager: Use common runtime host handler
  ([#4926](https://github.com/oasisprotocol/oasis-core/issues/4926))

- Bump tokio to 1.20.x
  ([#4928](https://github.com/oasisprotocol/oasis-core/issues/4928))

- keymanager: Refactor and reorganize runtime-related crates
  ([#4930](https://github.com/oasisprotocol/oasis-core/issues/4930))

- runtime/consensus/tendermint/verifier: Refactor verifier
  ([#4934](https://github.com/oasisprotocol/oasis-core/issues/4934))

- runtime: Add current sender sequence number to CheckTxMeta
  ([#4956](https://github.com/oasisprotocol/oasis-core/issues/4956))

- runtime-loader: Remove unused ELF loader
  ([#4969](https://github.com/oasisprotocol/oasis-core/issues/4969))

- mkvs/proof: Make sure that all entries in the proof have been used
  ([#4973](https://github.com/oasisprotocol/oasis-core/issues/4973))

  Note that this does not impact verification correctness as only visited
  nodes are part of the proof computation and the verified tree returned
  by the verifier.

  But in case future code may want to do something with raw entries of a
  verified proof this removes a possible footgun where unverified entries
  could be considered.

## 22.1 (2022-04-01)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 6.0.0     |
| Runtime Host      | 5.0.0     |
| Runtime Committee | 4.0.0     |

### Upgrading From Previous Versions

Previous versions allowed running Oasis Node (i.e. the `oasis-node` binary) as
root (effective user ID of 0).
As of this version, this is no longer allowed and attempting to run the
`oasis-node` process as the root user will now terminate immediately on startup.

### Removals and Breaking Changes

- governance: Allow unregistered nodes in votes
  ([#4607](https://github.com/oasisprotocol/oasis-core/issues/4607))

  The intent from the comments is to allow votes to be cast as long as the
  entity has at least 1 validator in the active set.  This fixes entities
  with nodes that are not currently registered having their votes rejected.

- go/consensus/tendermint: Record node liveness successes
  ([#4615](https://github.com/oasisprotocol/oasis-core/issues/4615))

- scheduler: Improve runtime committee election fairness
  ([#4623](https://github.com/oasisprotocol/oasis-core/issues/4623))

  Prune the per-entity nodes down to the per-runtime cap if configured,
  prior to doing the election, to improve fairness when entities opt to
  operate multiple nodes for the same runtime.

### Configuration Changes

- go/oasis-node/cmd/node: Do not allow running Oasis Node as root
  ([#4464](https://github.com/oasisprotocol/oasis-core/issues/4464))

  Nothing in Oasis Node will ever require elevated privileges.  Attempting
  to run the `oasis-node` process as the root user will now terminate
  immediately on startup.
  While there may be specific circumstances where it is safe to run network
  services with the effective user ID set to 0, the overwhelming majority of
  cases where this is done is a misconfiguration.

  If the previous behavior is required, the binary must be run in
  unsafe/debug mode (via the intentionally undocumented flag), and
  `debug.allow_root` must also be set.

- go/worker/storage: Storage checkpoints are now disabled by default
  ([#4561](https://github.com/oasisprotocol/oasis-core/issues/4561))

  - The `worker.storage.checkpointer.disabled` flag is removed.

  - The `worker.storage.checkpointer.enabled` flag is added to allow enabling
    storage checkpoints.

### Features

- go/oasis-node/cmd/stake: Allow querying historical account info
  ([#4416](https://github.com/oasisprotocol/oasis-core/issues/4416),
   [#4620](https://github.com/oasisprotocol/oasis-core/issues/4620))

  The `oasis-node stake account info` CLI command now accepts `--height` flag
  which allows one to query an account's info at an arbitrary height.

- go/oasis-node/cmd/node: Do not allow running Oasis Node as root
  ([#4464](https://github.com/oasisprotocol/oasis-core/issues/4464))

  Running network accessible services as the root user is extremely
  bad for system security as a general rule.  While it would be "ok"
  if we can drop privileges, `syscall.AllThreadsSyscall` does not
  work if the binary uses cgo at all.

- go/oasis-node/cmd/debug/bundle: Add `info` command
  ([#4546](https://github.com/oasisprotocol/oasis-core/issues/4546))

  Add `oasis-node debug bundle info` CLI command for inspecting runtime bundles.

- Randomize storage checkpoints wall-clock interval
  ([#4561](https://github.com/oasisprotocol/oasis-core/issues/4561))

- go/worker/registration: Add a random re-registration delay
  ([#4574](https://github.com/oasisprotocol/oasis-core/issues/4574))

- go/consensus/tendermint: Bump default max number of inbound peers
  ([#4576](https://github.com/oasisprotocol/oasis-core/issues/4576))

- go/worker: Add txsync protocol
  ([#4579](https://github.com/oasisprotocol/oasis-core/issues/4579))

  No longer clear tx pool on epoch transitions. Add the txsync protocol for
  syncing transaction between nodes.

- go/oasis-node/cmd/control: Add `clear-deregister` command
  ([#4580](https://github.com/oasisprotocol/oasis-core/issues/4580))

  Instead of using `--worker.registration.force_register` flag to clear the
  persisted deregister flag manually, there now is an explicit
  `oasis-node control clear-deregister` CLI command that will do so.

- runtime/host/sgx: Log the advisory URLs on attestation failure
  ([#4582](https://github.com/oasisprotocol/oasis-core/issues/4582))

- go/oasis-node/cmd: Preserve MKVS database by default in `unsafe-reset` command
  ([#4588](https://github.com/oasisprotocol/oasis-core/issues/4588))

  Preserving the MKVS database is becoming the more common workflow (i.e.
  keeping runtimes' state while wiping consensus state), so we're
  making that the default for `oasis-node unsafe-reset`.

  Use `--preserve.mkvs_database=false` to wipe the MKVS database as the
  previous default did.

- go/signature: Apply options on registered contexts
  ([#4591](https://github.com/oasisprotocol/oasis-core/issues/4591))

- go/oasis-node/cmd/control: Add `runtime-stats` command
  ([#4596](https://github.com/oasisprotocol/oasis-core/issues/4596))

  The new `oasis-node control runtime-stats` CLI command allows querying
  historical runtime statistics.

- Implements liveness and some other useful executor metrics
  ([#4610](https://github.com/oasisprotocol/oasis-core/issues/4610))

  The following Prometheus metrics were added:

  - `oasis_worker_executor_is_worker`
  - `oasis_worker_executor_is_backup_worker`
  - `oasis_worker_executor_committee_p2p_peers`
  - `oasis_worker_executor_liveness_total_rounds`
  - `oasis_worker_executor_liveness_live_rounds`
  - `oasis_worker_executor_liveness_live_ratio`

  See [metrics documentation] for descriptions of metrics.

  [metrics documentation]: https://docs.oasis.io/core/oasis-node/metrics

- go/oasis-node/cmd: Allow using non local gRPC connections
  ([#4617](https://github.com/oasisprotocol/oasis-core/issues/4617))

  Require server-side TLS for non unix-socket gRPC connections.

- go/worker/common: Lower default transaction recheck interval
  ([#4618](https://github.com/oasisprotocol/oasis-core/issues/4618))

### Bug Fixes

- go/common/identity: Save re-generated sentry client TLS certificate
  ([#4382](https://github.com/oasisprotocol/oasis-core/issues/4382))

  Sentry client TLS certificate is always re-generated from the private key when
  the Oasis Node starts.

  Previously, the re-generated sentry client TLS certificate was not saved to
  disk, which caused confusion since the on-disk certificate file (i.e.
  `sentry_client_tls_identity_cert.pem`) had incorrect/outdated expiry date.

- go/common/identity: Save re-generated node's persistent TLS certificate
  ([#4382](https://github.com/oasisprotocol/oasis-core/issues/4382))

  If a node's TLS certificate is persistent, it is always re-generated from the
  private key when the Oasis Node starts.

  Previously, the re-generated node's persistent TLS certificate was not saved
  to disk, which caused confusion since the on-disk certificate file (i.e.
  `tls_identity_cert.pem`) had incorrect/outdated expiry date.

- go/worker/common: Don't crash if current descriptor is not ready
  ([#4534](https://github.com/oasisprotocol/oasis-core/issues/4534))

- go/worker/beacon: Don't submit VRF proofs if registration disabled
  ([#4536](https://github.com/oasisprotocol/oasis-core/issues/4536))

- go/runtime/host/multi: Release lock before calling into runtime
  ([#4538](https://github.com/oasisprotocol/oasis-core/issues/4538))

- go/worker/common: Watch for all deployment updates when suspended
  ([#4541](https://github.com/oasisprotocol/oasis-core/issues/4541))

- go/worker/common: Properly refresh liveness statistics
  ([#4543](https://github.com/oasisprotocol/oasis-core/issues/4543))

- go/worker/storage: Only attempt checkpoint sync on initial startup
  ([#4544](https://github.com/oasisprotocol/oasis-core/issues/4544))

- go/oasis-node/cmd/ias: Refresh runtimes on every epoch
  ([#4548](https://github.com/oasisprotocol/oasis-core/issues/4548))

- go/worker/common: Propagate CheckTx errors
  ([#4551](https://github.com/oasisprotocol/oasis-core/issues/4551))

- consensus/sanity-checks: Skip suspended runtimes for computing stake claims
  ([#4556](https://github.com/oasisprotocol/oasis-core/issues/4556))

- runtime: Commit check transaction results for subsequent batches
  ([#4557](https://github.com/oasisprotocol/oasis-core/issues/4557))

- go/runtime/txpool: Abort runtime in case it times out during checks
  ([#4563](https://github.com/oasisprotocol/oasis-core/issues/4563))

- oasis-net-runner: Fix fixtures without a keymanager
  ([#4564](https://github.com/oasisprotocol/oasis-core/issues/4564))

- go/worker/registration: Clear deregister flag when deregistered
  ([#4580](https://github.com/oasisprotocol/oasis-core/issues/4580))

  When gracefully halting the node after the node's registration
  expires, to ensure that the deregistration and shutdown occurs,
  the node will persist the fact that it is mid-shutdown in a flag.

  Previously, this flag had to be cleared manually by the node operator
  which, while serving to ensure that the node does not get restarted
  and re-register, is sub-optimal as it required manual intervention.

  Instead, if the node is deregistered cleanly, we will clear the flag
  under the assumption that the operator can configure whatever
  automation they are using to do the right thing.

- go/registry: Fix invalid sanity check
  ([#4585](https://github.com/oasisprotocol/oasis-core/issues/4585))

- go/worker/registration: Fix shutdown if registration never succeeded
  ([#4595](https://github.com/oasisprotocol/oasis-core/issues/4595))

  This fixes a case where node would never shutdown if the initial
  registration never succeeded.

- go/registry: Fix node stake claim sanity check with suspended runtimes
  ([#4603](https://github.com/oasisprotocol/oasis-core/issues/4603))

### Internal Changes

- go: The libp2p logs are now emitted via Oasis Node's logging system
  ([#4531](https://github.com/oasisprotocol/oasis-core/issues/4531))

- go/runtime/bundle: Verify SGX signature if present
  ([#4542](https://github.com/oasisprotocol/oasis-core/issues/4542))

- go: Bump libp2p to 0.18.0
  ([#4562](https://github.com/oasisprotocol/oasis-core/issues/4562),
   [#4568](https://github.com/oasisprotocol/oasis-core/issues/4568),
   [#4578](https://github.com/oasisprotocol/oasis-core/issues/4578))

- go/worker/storage: Remove separate storage sync status store
  ([#4565](https://github.com/oasisprotocol/oasis-core/issues/4565))

  Previously the worker maintained a separate store that kept information about
  the progress of storage sync. Since it was a separate store this could cause
  problems if it got out of sync (e.g. due to partial manual copies). This
  should make the process more robust as there is only one source of truth.

- Remove `worker.registration.debug.private_key` flag
  ([#4595](https://github.com/oasisprotocol/oasis-core/issues/4595))

  The flag was unused.

- ci: Show dirtiness after regenerating protos
  ([#4598](https://github.com/oasisprotocol/oasis-core/issues/4598))

- go/common/crypto/signature: Improve the batch verification API
  ([#4602](https://github.com/oasisprotocol/oasis-core/issues/4602))

- go/upgrade: Add empty upgrade handler
  ([#4616](https://github.com/oasisprotocol/oasis-core/issues/4616))

- go: Bump github.com/opencontainers/image-spec to 1.0.2
  ([#4629](https://github.com/oasisprotocol/oasis-core/issues/4629))

- go: Bump github.com/opencontainers/runc to 1.0.3
  ([#4629](https://github.com/oasisprotocol/oasis-core/issues/4629))

## 22.0 (2022-03-01)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 5.0.0     |
| Runtime Host      | 5.0.0     |
| Runtime Committee | 4.0.0     |

### Removals and Breaking Changes

- go/registry/api: Lower minimum runtime round timeout
  ([#4090](https://github.com/oasisprotocol/oasis-core/issues/4090))

  The minimum runtime round timeout was previously 5 consensus blocks, but
  any non-zero positive value is now allowed.

- go/common/node: Add `SoftwareVersion` to the node descriptor
  ([#4212](https://github.com/oasisprotocol/oasis-core/issues/4212))

  This is an opaque string that is totally ignored by the consensus
  layer, populated with `go/common/version.SoftwareVersion` for
  diagnostic purposes.

- go/beacon: Add support for, and switch to VRF based elections defined in
  [ADR 0010]
  ([#4248](https://github.com/oasisprotocol/oasis-core/issues/4248))

  [ADR 0010]:
    https://github.com/oasisprotocol/adrs/blob/main/0010-vrf-elections.md

- Remove runtime genesis state parameter
  ([#4308](https://github.com/oasisprotocol/oasis-core/issues/4308))

  Runtimes are now expected to initialize genesis state on their own when
  processing the first block. Existing runtimes that use the Oasis SDK already
  do that.

- Remove separate storage committee
  ([#4308](https://github.com/oasisprotocol/oasis-core/issues/4308))

  This removes the need for a separate storage committee and instead treats the
  compute executor committee as the storage committee, greatly simplifying the
  protocol and opening a way towards further performance optimizations.

- go/governance: Replace `Quorum`/`Threshold` parameters with `StakeThreshold`
  ([#4309](https://github.com/oasisprotocol/oasis-core/issues/4309))

  This replaces the old quorum + threshold based governance proposal
  verification with a single unified threshold that represents the percentage of
  yes votes in terms of total voting power for a governance proposal to pass.

  The `oasis-node debug fix-genesis` command's conversion logic will convert the
  existing parameters to a stake threshold of 68%.

- go/roothash: Persist last round results in consensus state
  ([#4316](https://github.com/oasisprotocol/oasis-core/issues/4316))

  Previously last normal round results were only available as events at the
  height where the runtime block was emitted. This caused problems when
  consensus state sync was used as that block may not be available. Last rounds
  results are now persisted in consensus state so they remain always available.

- go/roothash: Add incoming runtime messages as defined in [ADR 0011]
  ([#4415](https://github.com/oasisprotocol/oasis-core/issues/4415))

  <!-- markdownlint-disable line-length -->
  [ADR 0011]:
    https://github.com/oasisprotocol/adrs/blob/main/0011-incoming-runtime-messages.md
  <!-- markdownlint-enable line-length -->

- go/staking: `DebondEndTime` is added to the `DebondingStartEscrowEvent`
  ([#4437](https://github.com/oasisprotocol/oasis-core/issues/4437))

  `DebondEndTime` is the epoch at the start of which the debonding escrow
  will be reclaimed.

  ```golang
  type DebondingStartEscrowEvent struct {
          Owner           Address           `json:"owner"`
          Escrow          Address           `json:"escrow"`
          Amount          quantity.Quantity `json:"amount"`
          ActiveShares    quantity.Quantity `json:"active_shares"`
          DebondingShares quantity.Quantity `json:"debonding_shares"`

          // Added.
          DebondEndTime   beacon.EpochTime `json:"debond_end_time"`
  }
  ```

- go/staking: Add minimum transfer amount
  ([#4456](https://github.com/oasisprotocol/oasis-core/issues/4456))

  A new consensus parameter `MinTransferAmount` (similar to the existing
  `MinDelegationAmount`) allows the network to reject small transfers.

- go/worker/storage: Transition storage sync to P2P
  ([#4459](https://github.com/oasisprotocol/oasis-core/issues/4459))

- go/staking: Add minimum transact balance
  ([#4461](https://github.com/oasisprotocol/oasis-core/issues/4461))

  In addition to a transaction fee, making a transaction requires that the
  sender has at least a minimum general staking balance.

  A new consensus parameter `MinTransactBalance` allows the network to enforce
  this behavior.

  Some staking methods now abort when they previously would have caused accounts
  to go below this minimum general staking balance.

- consensus: Base64 encode all tendermint event values
  ([#4465](https://github.com/oasisprotocol/oasis-core/issues/4465))

  Tendermint 0.35 requires all events to be actual strings and doesn't support
  binary data anymore. It also requires no dashes in attribute keys.

  Although Oasis Core still uses Tendermint 0.34, events are updated now to
  avoid breaking changes later.

- Add support for node suspension due to runtime liveness failures
  ([#4470](https://github.com/oasisprotocol/oasis-core/issues/4470))

- go/runtime/txpool: Refactor runtime scheduling queue
  ([#4477](https://github.com/oasisprotocol/oasis-core/issues/4477))

  Remove the `algorithm` field from the runtime descriptor as it is unused.
  Refactor the runtime transaction pool as it can be simplified now that there
  is just one algorithm.

- go/common/cbor: Bump decoding limits
  ([#4478](https://github.com/oasisprotocol/oasis-core/issues/4478))

- go/worker/keymanager: Transition keymanager protocol to P2P
  ([#4490](https://github.com/oasisprotocol/oasis-core/issues/4490))

- go/worker/storage: Transition public storage RPC to P2P
  ([#4500](https://github.com/oasisprotocol/oasis-core/issues/4500))

### Configuration Changes

- runtime: Change `OASIS_STRICT_AVR_VERIFY` to `OASIS_UNSAFE_LAX_AVR_VERIFY`
  ([#4055](https://github.com/oasisprotocol/oasis-core/issues/4055))

  Previous builds would default to lax verification.  After this change
  the default verify behavior will be the strict (requires `OK` quote
  status), unless `OASIS_UNSAFE_LAX_AVR_VERIFY` is set.

  NOTE: As with previously, this option has no effect if AVR verification
  is disabled entirely.

- Introducing the runtime mode
  ([#4308](https://github.com/oasisprotocol/oasis-core/issues/4308),
   [#4520](https://github.com/oasisprotocol/oasis-core/issues/4520))

  Instead of separately configuring various roles for a node, there is now a
  single configuration flag called `runtime.mode` which enables the correct
  roles as needed. It should be set to one of the following values:

  - `none` (runtime support is disabled, only consensus layer is enabled)
  - `compute` (node is participating as a runtime compute node for all the
    configured runtimes)
  - `keymanager` (node is participating as a keymanager node)
  - `client` (node is a stateful runtime client)
  - `client-stateless` (node is a stateless runtime client and connects to
    remote nodes for any state queries)

  Nodes that have so far been participating as compute nodes should set the mode
  to `compute` and nodes that have been participating as clients for querying
  and transaction submission should set it to `client`.

  The following configuration flags have been removed:

  - `runtime.supported` (existing `runtime.paths` is used instead)
  - `worker.p2p.enabled` (now automatically set based on runtime mode)
  - `worker.compute.enabled` (now set based on runtime mode)
  - `worker.keymanager.enabled` (now set based on runtime mode)
  - `worker.storage.enabled` (no longer needed)
  - `worker.storage.root_cache.apply_lock_lru_slots` (no longer needed)

- Switch to unified runtime bundles
  ([#4469](https://github.com/oasisprotocol/oasis-core/issues/4469))

  Instead of distributing runtime binaries separately and having the node
  operators configure the appropriate binary based on runtime ID, runtime
  artifacts are now distributed under a single self-describing "fat"
  bundle file.

  To configure runtimes the new syntax is:

  ```yaml
  runtime:
    paths:
      - examplepath/runtime.orc
      - anotherExamplePath/anotherRuntime.orc
  ```

  If the commandline is being used `runtime.paths` now only takes the path
  to the runtime bundle(s).

  This requires downloading new builds of the runtime binaries that are
  packaged in this format.

### Features

- go/oasis-node/cmd/consensus: Add `next_block_state` command
  ([#4241](https://github.com/oasisprotocol/oasis-core/issues/4241))

  This adds the `oasis-node consensus next_block_state` CLI command that shows
  the consensus voting status of the next block, primarily intended for
  debugging and monitoring upgrades.

- go/runtime/client: Add missing `GetTransactionsWithResults` method
  ([#4295](https://github.com/oasisprotocol/oasis-core/issues/4295))

- go/common: Use entire error as error message
  ([#4298](https://github.com/oasisprotocol/oasis-core/issues/4298))

- go/runtime/host/sgx: Autodetect SGX device name
  ([#4333](https://github.com/oasisprotocol/oasis-core/issues/4333))

- go/runtime/client: Add last retained round query
  ([#4334](https://github.com/oasisprotocol/oasis-core/issues/4334))

  This allows clients to query what is the earliest runtime round that the
  give node is storing.

- go/runtime/scheduling: Allow a higher priority tx even if queue is full
  ([#4431](https://github.com/oasisprotocol/oasis-core/issues/4431))

- go/worker/common: Report locally supported runtime host versions
  ([#4436](https://github.com/oasisprotocol/oasis-core/issues/4436))

- Add support for runtime schedule control
  ([#4438](https://github.com/oasisprotocol/oasis-core/issues/4438))

  This feature gives runtimes control over scheduling transactions inside a
  block, so the runtimes may implement their own more advanced policies.

- Add support for runtime message results as defined in [ADR 0012]
  ([#4443](https://github.com/oasisprotocol/oasis-core/issues/4443))

  <!-- markdownlint-disable line-length -->
  [ADR 0012]:
    https://github.com/oasisprotocol/adrs/blob/main/0012-runtime-message-results.md
  <!-- markdownlint-enable line-length -->

- go/runtime: Downtime-less runtime updates
  ([#4449](https://github.com/oasisprotocol/oasis-core/issues/4449))

  Runtime descriptors now include information regarding supported versions,
  and the epoch from which they are valid, so that updates can happen without
  incurring downtime by having upgrades and the descriptor change pre-staged
  well in advance of the upgrade epoch.

  NOTE: In the initial implementation, SGX enclaves will take an unavoidable
  1 epoch of downtime (the epoch when the upgrade takes effect), as allowing
  attestation for provisional (i.e. may never become valid) enclaves seems
  moderately risky.

- go/oasis-node: Implement unified runtime bundles
  ([#4469](https://github.com/oasisprotocol/oasis-core/issues/4469))

  This changes runtime bundles to be unified across all supported TEE types
  and self describing so that configuring runtimes is only a matter of passing
  in the runtime bundle file.

- tendermint: Bump to version 0.34.15-oasis1
  ([#4481](https://github.com/oasisprotocol/oasis-core/issues/4481))

- go/worker/common: Report liveness statistics in runtime status
  ([#4524](https://github.com/oasisprotocol/oasis-core/issues/4524))

  The `control status` output will now show something like the following for
  nodes which are currently in the executor committee:

  ```json
    "liveness": {
      "total_rounds": 78,
      "live_rounds": 77
    },
  ```

  The information comes from the consensus layer's liveness statistics for the
  current epoch. One can derive the node's liveness percentage as
  `live_rounds / total_rounds`.

### Bug Fixes

- go/common/identity: Don't forget to refresh TLS certificate
  ([#4289](https://github.com/oasisprotocol/oasis-core/issues/4289))

- go/worker/storage: Fix potential memory leak through context
  ([#4290](https://github.com/oasisprotocol/oasis-core/issues/4290))

- go/storage/api: Handle context cancellation in `receiveWriteLogIterator`
  ([#4292](https://github.com/oasisprotocol/oasis-core/issues/4292))

- go/worker/storage: Configure `GetDiff` timeout
  ([#4296](https://github.com/oasisprotocol/oasis-core/issues/4296))

- go: Make sure correct namespace/hash text serialization is used
  ([#4303](https://github.com/oasisprotocol/oasis-core/issues/4303))

- go/worker/storage: Handle state sync before runtime is operational
  ([#4311](https://github.com/oasisprotocol/oasis-core/issues/4311))

  Previously, there was an edge case that was not handled when the runtime was
  registered in the consensus layer but not yet operational (e.g. there have
  been no normal blocks yet). If a new node used state sync to quickly catch up
  with the consensus layer and sync to a height after runtime's genesis, the
  node would never register as it would keep waiting for storage checkpoints
  (which wouldn't exist yet).

- go/oasis-node/cmd: Add missing namespace to `LatestStateRoot`
  ([#4317](https://github.com/oasisprotocol/oasis-core/issues/4317))

- go/worker/compute: Handle round results at genesis
  ([#4317](https://github.com/oasisprotocol/oasis-core/issues/4317))

- go/consensus/tendermint: Only reset executor pool after emitting block
  ([#4323](https://github.com/oasisprotocol/oasis-core/issues/4323))

  Make sure to only reset the executor pool after any timeouts have been
  cleared (e.g. when an empty block is emitted) as otherwise there could be a
  stale timeout.

- go/runtime/client: `SubmitTxNoWait` should propagate `CheckTx` error
  ([#4328](https://github.com/oasisprotocol/oasis-core/issues/4328))

- go/staking: Fix incorrect non-existence check
  ([#4340](https://github.com/oasisprotocol/oasis-core/issues/4340))

- go/runtime/history: Limit batch size when pruning rounds
  ([#4345](https://github.com/oasisprotocol/oasis-core/issues/4345))

- go/consensus/tendermint/roothash: Only index the correct runtime
  ([#4351](https://github.com/oasisprotocol/oasis-core/issues/4351))

  In case multiple runtimes were being tracked, the indexing process could
  incorrectly set the last indexed round which could make it skip to index a
  round.

- oasis-node: Make Semver parsing less strict
  ([#4366](https://github.com/oasisprotocol/oasis-core/issues/4366))

  Semantic version parsing behavior changed in [#4343] was too strict. This fix
  changes parsing of versions so that only major component is required whereas
  minor and patch are optional and any remaining components are ignored.

  [#4343]: https://github.com/oasisprotocol/oasis-core/issues/4343

- go/storage/mkvs: Don't fail sanity check for equal roots
  ([#4381](https://github.com/oasisprotocol/oasis-core/issues/4381))

  In case the state root did not change, a write log is empty and so the sanity
  check should not require that it exists.

- runtime: Propagate panics during transaction/local RPC/policy dispatch
  ([#4386](https://github.com/oasisprotocol/oasis-core/issues/4386))

  A panic during transaction/local RPC/policy dispatch signals a serious
  problem so it should be propagated and the runtime should crash to force
  state reset.

- go/runtime/client: Take storage into account in `GetLastRetainedBlock`
  ([#4387](https://github.com/oasisprotocol/oasis-core/issues/4387))

- go/worker/storage: Checkpoint correct round on consensus checkpoint
  ([#4387](https://github.com/oasisprotocol/oasis-core/issues/4387))

- go/storage/client: Catch `GetDiff` errors early
  ([#4397](https://github.com/oasisprotocol/oasis-core/issues/4397))

- go/worker/storage: Limit number of rounds to fetch before applying them
  ([#4403](https://github.com/oasisprotocol/oasis-core/issues/4403))

  Previously, when a node was syncing from genesis, it would try to fetch all
  unapplied rounds before applying them.
  This could mean trying to fetch 100k+ rounds before applying them.
  In combination with failing to fetch rounds and random retrying, this could
  make the syncing process unbearably slow.

- go/storage/api: Make metrics wrapper return proper types
  ([#4411](https://github.com/oasisprotocol/oasis-core/issues/4411))

  Previously, the metrics wrapper tried to support all of the different backend
  interfaces, causing problems with places that perform type checks to
  determine which backend type is in use.

  The metrics wrapper is now changed to return a type matching the wrapped
  backend type.

- go/runtime/transaction: Return transactions in batch order when queried
  ([#4429](https://github.com/oasisprotocol/oasis-core/issues/4429))

  Previously, when runtime transactions were queried via a `GetTransactions`
  call, they were returned ordered by transaction hash instead of in execution
  order.

- runtime: Switch to the upstream jsonrpc package
  ([#4439](https://github.com/oasisprotocol/oasis-core/issues/4439))

- go/runtime/scheduling: Attempt to continue scheduling
  ([#4453](https://github.com/oasisprotocol/oasis-core/issues/4453))

- runtime: Fix `registry.Roothash` serialization
  ([#4460](https://github.com/oasisprotocol/oasis-core/issues/4460))

  Brings the `staking_params_are_empty` method up to date and adds some
  additional serialization tests.

- Allow launching enclaves with `SW_HARDENING_NEEDED` quote status
  ([#4491](https://github.com/oasisprotocol/oasis-core/issues/4491))

### Documentation Improvements

- [ADR 0010]: VRF-based Committee Elections
  ([#4248](https://github.com/oasisprotocol/oasis-core/issues/4248))

- [ADR 0011]: Incoming Runtime Messages
  ([#4327](https://github.com/oasisprotocol/oasis-core/issues/4327))

- [ADR 0012]: Runtime Message Results
  ([#4392](https://github.com/oasisprotocol/oasis-core/issues/4392))

- Migrate [Oasis Core Docs] to Docusaurus
  ([#4501](https://github.com/oasisprotocol/oasis-core/issues/4501))

  [Oasis Core Docs]: https://docs.oasis.io/core/

### Internal Changes

- Use typed attributes in all consensus services
  ([#4034](https://github.com/oasisprotocol/oasis-core/issues/4034))

  Beacon, keymanager, registry, roothash and scheduler events are updated to use
  the typed event attribute API.

- go: Bump fxamacker/cbor to 2.3.0
  ([#3986](https://github.com/oasisprotocol/oasis-core/issues/3986))

- common/node: Verify AVR quote status
  ([#4055](https://github.com/oasisprotocol/oasis-core/issues/4055))

  When verifying a `TEECapabilities` structure, additionally verify the
  quote status against the new `SGXConstraints.AllowedQuoteStatuses` vector
  so that nodes that have an invalid quote status can be omitted from
  scheduling entirely.

  NOTE: `QuoteOK` is ALWAYS allowed, as disallowing it is nonsensical.

- Setup rust code lints
  ([#4170](https://github.com/oasisprotocol/oasis-core/issues/4170))

- go/roothash: Remove unused `commitment.SignatureVerifier`
  ([#4308](https://github.com/oasisprotocol/oasis-core/issues/4308))

- go/worker/client: Move runtime client to a worker
  ([#4308](https://github.com/oasisprotocol/oasis-core/issues/4308))

- runtime: Bump tendermint-rs to 0.23.1
  ([#4365](https://github.com/oasisprotocol/oasis-core/issues/4365))

- Bump Go to 1.17.3 and Rust to nightly-2021-11-04
  ([#4375](https://github.com/oasisprotocol/oasis-core/issues/4375))

- tests/workload/runtime: Wait for 3rd epoch for compute nodes to be up
  ([#4395](https://github.com/oasisprotocol/oasis-core/issues/4395))

  Since the VRF-based scheduler was introduced the compute nodes only become
  eligible for election in the third epoch after genesis.

- go/consensus/tendermint/api: Add transaction context
  ([#4426](https://github.com/oasisprotocol/oasis-core/issues/4426))

  The old way of doing checkpoints is removed as the new transaction context
  supports nesting and event isolation.

- go/common/crypto/signature: Add static entropy provider for P2P roles
  ([#4459](https://github.com/oasisprotocol/oasis-core/issues/4459))

- go/worker/common/p2p: Add support for RPC protocols over P2P
  ([#4459](https://github.com/oasisprotocol/oasis-core/issues/4459))

- go/common/dynlib: Embed dynlib
  ([#4513](https://github.com/oasisprotocol/oasis-core/issues/4513))

## 21.3 (2021-09-27)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 4.0.0     |
| Runtime Host      | 4.0.0     |
| Runtime Committee | 3.0.0     |

### Removals and Breaking Changes

- runtime: Remove `runtime`, `tags` and `messages` context fields
  ([#3572](https://github.com/oasisprotocol/oasis-core/issues/3572))

  The test runtime is refactored to stop relying on those fields and behave
  like a simplified version of the dispatcher in the SDK.

- runtime: Remove `storage::StorageContext`
  ([#3572](https://github.com/oasisprotocol/oasis-core/issues/3572))

  The storage context was deprecated and has now been removed.

- go/runtime: Remove tag indexer
  ([#3888](https://github.com/oasisprotocol/oasis-core/issues/3888))

  The tag indexer is slow, buggy and unused by the SDK. Runtime transaction
  indexing and querying capabilities should be provided as part of the new
  event streaming API.

- runtime: Verify consensus layer state by using a light client
  ([#3952](https://github.com/oasisprotocol/oasis-core/issues/3952))

- go/runtime/client: Remove deprecated `GetTxs` method
  ([#3983](https://github.com/oasisprotocol/oasis-core/issues/3983))

  The `GetTxs` method has been deprecated and removed. Users should migrate
  to use `GetTransactions` instead.

- oasis-node: Remove opentracing and jaeger support
  ([#4011](https://github.com/oasisprotocol/oasis-core/issues/4011))

  This is breaking as it deprecates a feature from the node binary, and alters
  both the P2P and runtime/host communication protocols.

- go/ias-proxy: remove the debug `use genesis` option
  ([#4098](https://github.com/oasisprotocol/oasis-core/issues/4098))

- go/oasis-node: Prevent startup when file descriptor limit is too low
  ([#4192](https://github.com/oasisprotocol/oasis-core/issues/4192))

  Before, a warning was emitted if file descriptor limit was low (below 1024).
  Since low file descriptor limit can cause problems with BadgerDB, a
  high enough limit is now required on node startup (at least 50000).

  Follow the [File Descriptor Limit] documentation page for details on how to
  increase the limit on your system.

  <!-- markdownlint-disable line-length -->
  [File Descriptor Limit]:
    /general/run-a-node/prerequisites/system-configuration#file-descriptor-limit
  <!-- markdownlint-enable line-length -->

- runtime: Deprecate `transaction::MethodDispatcher`
  ([#4198](https://github.com/oasisprotocol/oasis-core/issues/4198))

- runtime: Deprecate the old `MethodDispatcher` related types
  ([#4201](https://github.com/oasisprotocol/oasis-core/issues/4201))

- go/roothash: Remove `GetLatestBlock` from `BlockHistory` interface
  ([#4217](https://github.com/oasisprotocol/oasis-core/issues/4217))

  Instead developers should use `GetBlock` or `GetAnnotatedBlock` with the
  special `RoundLatest` value to get the latest block or annotated block.

- go/scheduler: Remove `debug_static_validators` consensus parameter
  ([#4222](https://github.com/oasisprotocol/oasis-core/issues/4222))

  The option was only used in unit tests and required some special handling.

- go/runtime: Remove obsolete transaction types
  ([#4228](https://github.com/oasisprotocol/oasis-core/issues/4228))

  The deprecated types `TxnCall`, `TxnOutput` and `TxnCheckResult` have been
  removed. Any users should consider migrating to the Runtime SDK or copying
  the type definitions in case they still rely on them.

- runtime: Add `MaxMessages` to `CheckTxBatch` and `Query`
  ([#4231](https://github.com/oasisprotocol/oasis-core/issues/4231))

  This allows transaction checks and queries to access the maximum number of
  runtime messages that can be emitted per round. Previously this information
  was only available in `ExecuteTxBatch`.

- keymanager-api-common: Implement `Zeroize` for secret types
  ([#4242](https://github.com/oasisprotocol/oasis-core/issues/4242))

- Remove EnclaveRPC client gRPC interface
  ([#4244](https://github.com/oasisprotocol/oasis-core/issues/4244))

  Since the SDK now supports using the key manager, the idea is that EnclaveRPC
  calls should be done from the runtime and exposed via queries.

- runtime: Make storage cache capacity configurable
  ([#4264](https://github.com/oasisprotocol/oasis-core/issues/4264))

  Also changes the `start_runtime` method signature to accept a `Config` struct
  so that in the future adding various configuration is easier.

- runtime: Make dispatcher core async
  ([#4273](https://github.com/oasisprotocol/oasis-core/issues/4273))

  Note that this only affects the core and allows for parallel query processing
  which still happens in blocking threads. It does open the way for fully async
  query dispatch.

- runtime: Refactor protocol type, expose via `transaction::Context`
  ([#4276](https://github.com/oasisprotocol/oasis-core/issues/4276))

- go/common: Change `Namespace`'s text (un)marshaling to use the hex form
  ([#4279](https://github.com/oasisprotocol/oasis-core/issues/4279))

- go/common/crypto/hash: Change `Hash`'s text (un)marshaling to use the hex form
  ([#4279](https://github.com/oasisprotocol/oasis-core/issues/4279))

- runtime: Pass query arguments as arbitrary bytes
  ([#4280](https://github.com/oasisprotocol/oasis-core/issues/4280))

  This makes it more in line with execute/check requests which already accepted
  arbitrary bytes and it prevents malformed CBOR in query arguments from
  breaking the Runtime Host Protocol.

- go/consensus/api: Change `Block`'s `Hash` field type to the common `Hash` type
  ([#4281](https://github.com/oasisprotocol/oasis-core/issues/4281))

  Also change the type of `Status`' hash-related fields (`LatestHash`,
  `GenesisHash`, `LastRetainedHash`) to the [common `Hash` type] to allow nicer
  text/JSON serialization.

  <!-- markdownlint-disable line-length -->
  [common `Hash` type]:
    https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/crypto/hash#Hash
  <!-- markdownlint-enable line-length -->

### Configuration Changes

- go/runtime: Remove tag indexer
  ([#3888](https://github.com/oasisprotocol/oasis-core/issues/3888))

  The `runtime.history.tag_indexer.backend` configuration option has been
  removed.

- go/worker/common/p2p: Add flags controlling libp2p validator concurrency
  ([#4025](https://github.com/oasisprotocol/oasis-core/issues/4025))

  - `worker.p2p.validate_concurrency`: libp2p gossipsub per topic validator
      concurrency limit
  - `worker.p2p.validate_throttle`: libp2p gossipsub validator concurrency
      limit

- badger/migration: `badger.migrate.num_go_routines` flag
  ([#4037](https://github.com/oasisprotocol/oasis-core/issues/4037),
   [#4041](https://github.com/oasisprotocol/oasis-core/issues/4041))

  The flag enables controlling the number of go routines badger uses when
  doing the v2 -> v3 migration. Use the flag to lower memory pressure during
  the migration, by lowering the amount of workers to e.g. 1.

### Features

- go/worker/executor: Batch runtime `CheckTx` transactions
  ([#2548](https://github.com/oasisprotocol/oasis-core/issues/2548))

- go/staking: Add `DebondingStartEscrowEvent`
  ([#4014](https://github.com/oasisprotocol/oasis-core/issues/4014))

  This makes it easier to reason about the debonded amounts, both in shares and
  in base units.

- go/oasis-net-runner: Allow setting runtime provisioner
  ([#4024](https://github.com/oasisprotocol/oasis-core/issues/4024))

  On systems that do not support Bubblewrap, the runtime provisioner can be
  set to `unconfined`.

- go/oasis-net-runner: Allow running without a key manager
  ([#4024](https://github.com/oasisprotocol/oasis-core/issues/4024))

  This feature makes it easier to run debug runtimes that are not (yet)
  associated with a key manager.

- runtime-loader: Allow building for non-SGX use on platforms that aren't Linux
  ([#4024](https://github.com/oasisprotocol/oasis-core/issues/4024))

- oasis-net-runner: Support setting custom node arguments in fixtures
  ([#4025](https://github.com/oasisprotocol/oasis-core/issues/4025))

- Build `oasis-node` with `jemalloc` tag (used by BadgerDB)
  ([#4040](https://github.com/oasisprotocol/oasis-core/issues/4040),
   [#4046](https://github.com/oasisprotocol/oasis-core/issues/4046))

  In BadgerDB v3, using `jemalloc` seems to be recommended and better supported
  option ([1], [2]). Based on our experience, using `jemalloc` reduces BadgerDB
  memory usage.

  To build `oasis-node` without `jemalloc` requirement, set the
  `OASIS_BADGER_NO_JEMALLOC="1"` environment variable before invoking the
  `Makefile`.

  [1]: https://dgraph.io/blog/post/manual-memory-management-golang-jemalloc/
  [2]: https://discuss.dgraph.io/t/memory-issue-during-stream-operation/13033

- upgrade/migrations: Add max allowances upgrade handler
  ([#4064](https://github.com/oasisprotocol/oasis-core/issues/4064))

  Add `"consensus-staking-max-allowances-16"` upgrade handler which updates
  the consensus staking parameter `MaxAllowances` to `16`.

- go/common/errors: Expose runtime query error details to clients
  ([#4067](https://github.com/oasisprotocol/oasis-core/issues/4067))

- go/worker/storage: Synchronize checkpoints with consensus layer
  ([#4080](https://github.com/oasisprotocol/oasis-core/issues/4080))

- runtime/client: Add `SubmitTx` variant that includes metadata
  ([#4162](https://github.com/oasisprotocol/oasis-core/issues/4162))

- go/registry/api: Add its own body type to `MethodDeregisterEntity`
  ([#4177](https://github.com/oasisprotocol/oasis-core/issues/4177))

- upgrade/migrations: Add `consensus-params-update-2021-08` upgrade handler
  ([#4180](https://github.com/oasisprotocol/oasis-core/issues/4180))

- go/roothash/api/block: Use custom `Timestamp` type for block's header
  ([#4183](https://github.com/oasisprotocol/oasis-core/issues/4183))

  This enables prettier Oasis Node's `control status` CLI command's output
  for runtimes' `latest_time` field and matches the format of consensus'
  `latest_time` field.

- go/roothash/api: Add `ConsensusParameters` method
  ([#4187](https://github.com/oasisprotocol/oasis-core/issues/4187))

- go/consensus/tendermint: Request state refresh on consensus init
  ([#4237](https://github.com/oasisprotocol/oasis-core/issues/4237))

  Previously pending upgrade descriptors were only refreshed during governance
  proposal execution or after finishing a state sync. This is changed so that
  the `MessageStateSyncCompleted` message is also emitted after consensus
  initialization on already synced nodes so pending upgrades get installed even
  in case state was synced manually (out of band).

- go/common/node: Add custom text (un)marshaler for `RolesMask` type
  ([#4243](https://github.com/oasisprotocol/oasis-core/issues/4243))

  This will result in easy to understand `"roles"` fields in various CLI
  commands that output JSON.

- go/common/entity: Use pretty-printed JSON when saving entity to file
  ([#4266](https://github.com/oasisprotocol/oasis-core/issues/4266))

- go/oasis-node/cmd: Use pretty-printed variant when outputting JSON
  ([#4266](https://github.com/oasisprotocol/oasis-core/issues/4266))

- go/common/crypto/hash: Add `LoadFromHexBytes()` method to `Hash` type
  ([#4281](https://github.com/oasisprotocol/oasis-core/issues/4281))

- go/common/crypto/hash: Add `Hex()` method to `Hash` type
  ([#4281](https://github.com/oasisprotocol/oasis-core/issues/4281))

### Bug Fixes

- go/oasis-net-runner: Always honor `fixture.default.setup_runtimes`
  ([#4009](https://github.com/oasisprotocol/oasis-core/issues/4009))

- go/common/badger: Fix v2->v3 migration for managed mode
  ([#4010](https://github.com/oasisprotocol/oasis-core/issues/4010))

- go/storage/mkvs/checkpoint: Checkpoint in descending order
  ([#4010](https://github.com/oasisprotocol/oasis-core/issues/4010))

  Previously the checkpointer would generate checkpoints in ascending order
  which meant that it could generate many checkpoints only to garbage collect
  them in the next step.

- go/consensus/tendermint/apps/staking: Fix emitted reward events
  ([#4033](https://github.com/oasisprotocol/oasis-core/issues/4033))

- badger/migration: Keep only last version when migrating non-managed DB
  ([#4037](https://github.com/oasisprotocol/oasis-core/issues/4037))

  Even though Oasis Core always configures non-managed badger databases to keep
  a single version of keys, some databases in the wild contain multiple versions
  of the same key.

  Skip migrating more than the latest version when migrating non-managed
  badger databases.

- go/runtime/host/sandbox: Prevent restart storm after 10 minutes
  ([#4059](https://github.com/oasisprotocol/oasis-core/issues/4059))

- go/consensus/tendermint: Fix last retained version query
  ([#4060](https://github.com/oasisprotocol/oasis-core/issues/4060))

  Previously, the reported version was incorrect when the node used state sync
  and pruning was disabled.

- go/worker/executor: Do not route local storage applies via gRPC
  ([#4061](https://github.com/oasisprotocol/oasis-core/issues/4061))

- go/upgrade/api: Validate upgrade migration handler name on registration
  ([#4065](https://github.com/oasisprotocol/oasis-core/issues/4065))

- go/worker/storage: Add missing timeout for operations
  ([#4072](https://github.com/oasisprotocol/oasis-core/issues/4072))

- go/worker/storage: Don't crash on early query
  ([#4072](https://github.com/oasisprotocol/oasis-core/issues/4072))

- go/worker/storage: Force checkpoint sync when block info unavailable
  ([#4080](https://github.com/oasisprotocol/oasis-core/issues/4080))

- ias/proxy/client: Make `GetSigRL` not panic if IAS proxy not configured
  ([#4081](https://github.com/oasisprotocol/oasis-core/issues/4081))

- go/worker/executor: Skip proposer timeout if batch was received
  ([#4083](https://github.com/oasisprotocol/oasis-core/issues/4083))

- go/consensus/tendermint: Handle validator fetching error in `GetStatus()`
  ([#4085](https://github.com/oasisprotocol/oasis-core/issues/4085))

- go/worker/common: Always use naked local storage
  ([#4093](https://github.com/oasisprotocol/oasis-core/issues/4093))

  Previously the committee group could incorrectly use the synced version of
  the local backend which could block operations resulting in failure to fetch
  data.

- go/storage/api/mux: Don't return an error on a successful read
  ([#4093](https://github.com/oasisprotocol/oasis-core/issues/4093))

- go/storage/mkvs/checkpoint: Determine next offset correctly
  ([#4096](https://github.com/oasisprotocol/oasis-core/issues/4096))

- go/worker/compute: Replicate input batch locally
  ([#4107](https://github.com/oasisprotocol/oasis-core/issues/4107))

  Previously, storage commit could fail in case the node was both an executor
  and a storage node but not in the storage committee.

- go/consensus/tendermint: Correctly propagate errors
  ([#4110](https://github.com/oasisprotocol/oasis-core/issues/4110))

  Not propagating the state unavailable error could lead to corruption when the
  database becomes unavailable (e.g., due to running out of space or file
  descriptors).

- go/runtime/host/sandbox: Add deadline to Bubblewrap pipes
  ([#4111](https://github.com/oasisprotocol/oasis-core/issues/4111))

  This prevents the constructor from blocking forever in case something is
  wrong with the sandbox setup.

- go/runtime/client: Fail `SubmitTx` early for unsupported runtimes
  ([#4202](https://github.com/oasisprotocol/oasis-core/issues/4202))

  Make sure that the runtime is actually among the supported runtimes as
  otherwise we will not be able to actually get any results back.

- go/runtime: Fix ignored round in runtime `Query`
  ([#4210](https://github.com/oasisprotocol/oasis-core/issues/4210))

- go/runtime/client: Wait for hosted runtime provisioning
  ([#4214](https://github.com/oasisprotocol/oasis-core/issues/4214))

  Previously an early runtime `Query` or `CheckTx` could fail if the locally
  hosted runtime was just being provisioned. This makes it wait for the
  provisioning to complete instead.

- go/common/identity: Refresh sentry TLS certificates
  ([#4239](https://github.com/oasisprotocol/oasis-core/issues/4239))

  Since we are using public keys for TLS authentication, we make sure that
  sentry TLS certificates are refreshed to avoid them expiring.

- go/runtime: Add key manager EnclaveRPC support to client runtime hosts
  ([#4244](https://github.com/oasisprotocol/oasis-core/issues/4244))

  Previously, runtimes hosted on client nodes were not able to issue EnclaveRPC
  requests as the endpoint was not implemented in the handler. This unifies the
  handler implementations between the client and compute nodes and makes sure
  that key manager requests are possible (of course client nodes will only be
  able to request public keys).

- go/upgrade: EnsureCompatible should only check consensus
  ([#4267](https://github.com/oasisprotocol/oasis-core/issues/4267))

- go/common/grpc: Configure max message size on the client
  ([#4268](https://github.com/oasisprotocol/oasis-core/issues/4268))

### Documentation Improvements

- Update example output of `oasis-node control status` CLI command
  ([#4281](https://github.com/oasisprotocol/oasis-core/issues/4281))

### Internal Changes

- go: Bump github.com/dgraph-io/badger/v3 from 3.2011.1 to 3.2103.1
  ([#4003](https://github.com/oasisprotocol/oasis-core/issues/4003),
   [#4127](https://github.com/oasisprotocol/oasis-core/issues/4127))

- go: Bump github.com/prometheus/common from 0.25.0 to 0.28.0
  ([#4007](https://github.com/oasisprotocol/oasis-core/issues/4007))

- go: Bump github.com/prometheus/client_golang from 1.10.0 to 1.11.0
  ([#4008](https://github.com/oasisprotocol/oasis-core/issues/4008))

- runtime: Stop using webpki to validate the IAS cert chain
  ([#4021](https://github.com/oasisprotocol/oasis-core/issues/4021))

- runtime: Do not require `OASIS_STORAGE_PROTOCOL_SERVER_BINARY`
  ([#4023](https://github.com/oasisprotocol/oasis-core/issues/4023))

- go: Bump gitlab.com/yawning/dynlib to the latest version
  ([#4026](https://github.com/oasisprotocol/oasis-core/issues/4026))

- go/oasis-node/cmd/debug: Remove the `consim` sub-command
  ([#4030](https://github.com/oasisprotocol/oasis-core/issues/4030))

- go: Bump github.com/spf13/viper from 1.7.1 to 1.8.0
  ([#4032](https://github.com/oasisprotocol/oasis-core/issues/4032))

- go/consensus/tendermint: Add typed attribute API
  ([#4033](https://github.com/oasisprotocol/oasis-core/issues/4033))

  Using typed events makes it slightly harder to use an incorrect key/value
  combination. Unfortunately, we cannot use this in all of the cases due to
  events in `registry`/`roothash` not being nicely structured and changing this
  would require existing nodes to resync due to internal event key changes.

- build: Stuff to make CI faster
  ([#4038](https://github.com/oasisprotocol/oasis-core/issues/4038))

- ci: Fix dirty Git state in the release GitHub Actions workflow
  ([#4050](https://github.com/oasisprotocol/oasis-core/issues/4050))

- github: Unify jemalloc installation with GoReleaser installation in workflows
  ([#4052](https://github.com/oasisprotocol/oasis-core/issues/4052))

- go/common/backoff: Add `NewExponentialBackoff()` with sane defaults
  ([#4059](https://github.com/oasisprotocol/oasis-core/issues/4059))

- go/worker/common: Move committee storage to `Group`
  ([#4061](https://github.com/oasisprotocol/oasis-core/issues/4061))

- go/consensus/tendermint/apps/governance: Ensure upgrade is in progress
  ([#4070](https://github.com/oasisprotocol/oasis-core/issues/4070))

- go/storage/mkvs/checkpoint: Add `ForceCheckpoint()` and `WatchCheckpoints()`
  ([#4080](https://github.com/oasisprotocol/oasis-core/issues/4080))

- go/runtime: Delay subscriptions until after consensus sync
  ([#4080](https://github.com/oasisprotocol/oasis-core/issues/4080))

  Previously, if the node used consensus state sync it would fail to receive any
  updates for the various descriptors until the descriptors were updated after
  the state sync checkpoint.

- go/consensus: Expose consensus state checkpointer
  ([#4080](https://github.com/oasisprotocol/oasis-core/issues/4080))

- runtime: Bump bech32 to 0.8.1
  ([#4089](https://github.com/oasisprotocol/oasis-core/issues/4089))

- runtime: Bump tendermint to 0.20.0
  ([#4089](https://github.com/oasisprotocol/oasis-core/issues/4089))

- ci: Make jemalloc builds reproducible
  ([#4095](https://github.com/oasisprotocol/oasis-core/issues/4095))

- runtime: Use JSON-RPC for the mkvs interop helper
  ([#4101](https://github.com/oasisprotocol/oasis-core/issues/4101))

- go/worker/compute: Add runtime abort timeout to avoid blocking forever
  ([#4111](https://github.com/oasisprotocol/oasis-core/issues/4111))

- go/common/logging: Switch to go-kit/log module
  ([#4117](https://github.com/oasisprotocol/oasis-core/issues/4117))

  This is the only part of go-kit that we are using so it makes sense to switch
  to the smaller package.

- runtime: Switch from serde-cbor for oasis-cbor
  ([#4133](https://github.com/oasisprotocol/oasis-core/issues/4133),
   [#4278](https://github.com/oasisprotocol/oasis-core/issues/4278))

- rust: Bump rsa from 0.4.0 to 0.5.0
  ([#4147](https://github.com/oasisprotocol/oasis-core/issues/4147))

- runtime/simple-keyvalue: Check nonces
  ([#4154](https://github.com/oasisprotocol/oasis-core/issues/4154))

- storage/checkpoint_sync: Add timeout for fetching checkpoints from nodes
  ([#4155](https://github.com/oasisprotocol/oasis-core/issues/4155))

- workload/runtime: Ensure correct round for validating events
  ([#4161](https://github.com/oasisprotocol/oasis-core/issues/4161))

- go/registry/gen_vectors: Stop generating register transactions for v1 entities
  ([#4167](https://github.com/oasisprotocol/oasis-core/issues/4167))

- rust: Bump x509-parser from 0.9.2 to 0.10.0
  ([#4173](https://github.com/oasisprotocol/oasis-core/issues/4173))

- rust: Bump intrusive-collections to 0.9.2
  ([#4174](https://github.com/oasisprotocol/oasis-core/issues/4174))

- go: Update gofumpt to 0.1.1
  ([#4176](https://github.com/oasisprotocol/oasis-core/issues/4176))

- go/registry/gen_vectors: Add vectors for deregister entity transactions
  ([#4177](https://github.com/oasisprotocol/oasis-core/issues/4177))

- go/oasis-test-runner: Add support for testing upgrade handlers
  ([#4179](https://github.com/oasisprotocol/oasis-core/issues/4179))

- go: Update golangci-lint to 1.41.1
  ([#4190](https://github.com/oasisprotocol/oasis-core/issues/4190))

- rust/ci: Bump tarpaulin to 0.18.0
  ([#4197](https://github.com/oasisprotocol/oasis-core/issues/4197))

- rust: Update crossbeam-deque to 0.7.4/0.8.1
  ([#4209](https://github.com/oasisprotocol/oasis-core/issues/4209))

- rust: Bump tokio from 1.8.1 to 1.10.1
  ([#4213](https://github.com/oasisprotocol/oasis-core/issues/4213))

- go/oasis-test-runner: Add an E2E test for (un)freezing a slashed validator
  ([#4223](https://github.com/oasisprotocol/oasis-core/issues/4223))

- Bump Rust toolchain to 2021-08-17
  ([#4235](https://github.com/oasisprotocol/oasis-core/issues/4235))

- go: Bump github.com/libp2p/go-libp2p to 0.15.0
  ([#4257](https://github.com/oasisprotocol/oasis-core/issues/4257))

- go: Bump grpc to 1.40.0
  ([#4260](https://github.com/oasisprotocol/oasis-core/issues/4260))

- go/fixgenesis: Remove the not anymore relevant migration
  ([#4265](https://github.com/oasisprotocol/oasis-core/issues/4265))

- go/oasis-node/cmd/common: Add `PrettyJSONMarshal()` helper
  ([#4266](https://github.com/oasisprotocol/oasis-core/issues/4266))

- rust: Bump crypto-bigint to 0.2.10
  ([#4278](https://github.com/oasisprotocol/oasis-core/issues/4278))

- rust: Bump base64ct to 1.1.0
  ([#4278](https://github.com/oasisprotocol/oasis-core/issues/4278))

- rust: Bump zeroize_derive to 1.2.0
  ([#4282](https://github.com/oasisprotocol/oasis-core/issues/4282))

## 21.2 (2021-06-07)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 4.0.0 |
| Runtime Host      | 3.0.0 |
| Runtime Committee | 2.0.0 |

### Upgrading From Previous Versions

Due to a database backend upgrade introduced in this version (see below for
details), initial startup time will be longer as a full database migration needs
to be performed for each of the internal databases. *The migration may take
several minutes and requires enough free disk space to accommodate a copy of the
node's data directory.*

### Removals and Breaking Changes

- runtime: add support for transaction priority and weights
  ([#3760](https://github.com/oasisprotocol/oasis-core/issues/3760))

  Adds support for runtime transaction priority and weights that can be set by
  runtime in `CheckTx` response. Transactions are scheduled by priority (higher
  first). Transaction weights are used by scheduler when creating batches to
  ensure no batch passes the per round weight limit. Supported limits are:

  - `count` - number of transactions - per round limit is a runtime parameter in
    registry (already existed prior to this change).
  - `size_bytes` - size of transactions in bytes - per round limit is a runtime
    parameter in registry (already existed prior to this change).
  - `consensus_messages` - number of emitted consensus messages - per round
    limit is a consensus parameter (already existed prior to this change).
  - Custom, runtime specific weights. `internal.BatchWeightLimits` method is
    queried for custom batch weight limits on every round.

- runtime: Ensure compatible consensus versions
  ([#3823](https://github.com/oasisprotocol/oasis-core/issues/3823))

  Runtime now ensures host is running a compatible consensus version.
  This is a breaking runtime host protocol change as the version types in
  protocol are changed.

- runtime: Add support for block tags
  ([#3848](https://github.com/oasisprotocol/oasis-core/issues/3848))

- runtime: Add epoch to ExecuteTx/CheckTx/Query requests
  ([#3892](https://github.com/oasisprotocol/oasis-core/issues/3892))

- go/cmd/registry: simplify register runtime command
  ([#3903](https://github.com/oasisprotocol/oasis-core/issues/3903))

  The `registry runtime gen_register` command now accepts a JSON runtime
  descriptor, which should simplify generating runtime registration
  transactions.
  The `registy runtime init_genesis` command is removed as runtime
  descriptors in genesis are not singed since version 21.0+ making the command
  obsolete.

- staking: Include share amounts in `AddEscrow` and `ReclaimEscrow` events
  ([#3939](https://github.com/oasisprotocol/oasis-core/issues/3939))

- Update emitted events when disbursing rewards
  ([#3944](https://github.com/oasisprotocol/oasis-core/issues/3944))

  Before, a single `AddEscrow` event was emitted which did not correctly
  represent the actual state changes when rewards were disbursed.

  Now the following events are emitted:

  - `Transfer(CommonPool -> Recipient, commissionAmount)` event for the
    commissioned part of the reward
  - `AddEscrow(Recipient -> Recipient, commissionAmount)` event for the
    automatically escrowed commission reward
  - `AddEscrow(CommonPool -> Recipient, restAmount)` for the non-commissioned
    part of the reward (which only increases existing shares prices)

### Configuration Changes

- Change IAS proxy client authentication configuration
  ([#3958](https://github.com/oasisprotocol/oasis-core/issues/3958))

  Previously the full TLS certificate needed to be passed when configuring the
  IAS proxy client, but now only the public key needs to be included.

  The `ias.tls` configuration option is removed and `ias.proxy_addr` is
  renamed to `ias.proxy.address`. One can now configure multiple proxy
  addresses and each address needs to contain the Base64-encoded public key,
  for example: `<pubkey>@ias.oasis.dev`.

- go/worker/compute: remove `schedule_check_tx.enabled` flag
  ([#3965](https://github.com/oasisprotocol/oasis-core/issues/3965))

  Runtime executor workers now always call CheckTx before scheduling runtime
  transactions. The option to disable CheckTx for runtime transactions is
  removed.

### Features

- Bump Badger database to v3
  ([#3859](https://github.com/oasisprotocol/oasis-core/issues/3859))

  The old database will automatically be converted during the initial node
  startup. For this reason the following should be taken into account when
  upgrading:

  - Initial startup time will be longer as a full database migration needs to
    be performed for each of the internal databases. The migration may take
    several minutes.

  - In order to ensure a backup exists in the unlikely case that anything goes
    wrong with the migration, the old databases will be kept in the same
    location but with a `.backup` suffix. *For this reason, make sure that you
    have enough free disk space to accommodate a copy of the node's data
    directory.*

- runtime: Implement consensus staking layer state accessors
  ([#3564](https://github.com/oasisprotocol/oasis-core/issues/3564))

- Add support for local runtime-specific configuration
  ([#3776](https://github.com/oasisprotocol/oasis-core/issues/3776))

  Runtimes can now accept configuration local to the compute node that is
  running them. This is possible via the following configuration schema (can
  only be configured via a config file):

  ```yaml
  runtime:
    config:
      "8000000000000000000000000000000000000000000000000000000000000000":
        core:
          min_gas_price: 1
  ```

  This is useful to specify runtime-specific parameters like minimum gas price
  accepted by the node. Note that this configuration can only be used during
  non-deterministic transactions checks as it would otherwise result in a
  discrepancy.

- go/runtime/client: Add `GetTransactions` method, deprecate `GetTxs`
  ([#3812](https://github.com/oasisprotocol/oasis-core/issues/3812))

  A new method called `GetTransactions` has been added to replace the (now
  deprecated) `GetTxs`. The new method does not require the caller to pass
  the IO root as that is an internal detail. This makes it consistent with
  the existing `GetEvents` API.

  Users of `GetTxs` should migrate to `GetTransactions` as the former may be
  removed in a future release.

- go/roothash/api: Add gRPC service
  ([#3827](https://github.com/oasisprotocol/oasis-core/issues/3827))

- common/crypto/signature: Use curve25519-voi
  ([#3829](https://github.com/oasisprotocol/oasis-core/issues/3829))

  This Ed25519/X25519 implementation is faster and more maintainable that
  the previous in-house implementation.

- common/crypto/slip10: Add a SLIP-0010 implementation
  ([#3829](https://github.com/oasisprotocol/oasis-core/issues/3829))

  Needed for some wallet stuff, and it is the least-awful hierarchical
  derivation scheme for Ed25519.

- go/oasis-node/cmd/genesis: Display doc's hash and SHA256 checksum with `check`
  ([#3858](https://github.com/oasisprotocol/oasis-core/issues/3858))

- go/worker/compute: Propose block on runtime genesis
  ([#3894](https://github.com/oasisprotocol/oasis-core/issues/3894))

- go/oasis-node: Add storage namespace rename subcommand
  ([#3908](https://github.com/oasisprotocol/oasis-core/issues/3908))

- go/oasis-net-runner: default fixture support staking genesis
  ([#3914](https://github.com/oasisprotocol/oasis-core/issues/3914))

- go/oasis-net-runner: support multiple runtimes in default fixture
  ([#3914](https://github.com/oasisprotocol/oasis-core/issues/3914))

- go/common/crypto/sakg: Add [ADR 0008] implementation
  ([#3918](https://github.com/oasisprotocol/oasis-core/issues/3918))

  <!-- markdownlint-disable line-length -->
  [ADR 0008]:
    https://github.com/oasisprotocol/adrs/blob/main/0008-standard-account-key-generation.md
  <!-- markdownlint-enable line-length -->

- go/worker/compute: Propose block on new epoch
  ([#3987](https://github.com/oasisprotocol/oasis-core/issues/3987))

- go/oasis-node/cmd/debug/beacon: Initial import
  ([#3897](https://github.com/oasisprotocol/oasis-core/issues/3897))

  Add a `debug beacon status` command which queries the current beacon and
  PVSS backend state.

### Bug Fixes

- go/oasis-node: Dump correct block height on halt
  ([#3755](https://github.com/oasisprotocol/oasis-core/issues/3755))

- go/storage/mkvs: Skip already pruned nodes in migration
  ([#3857](https://github.com/oasisprotocol/oasis-core/issues/3857))

- Apply upgrade proposals directly from governance consensus application
  ([#3870](https://github.com/oasisprotocol/oasis-core/issues/3870))

  This should make it more robust in light of fast sync as otherwise the worker
  could miss upgrade events in certain edge cases.

- Runtime workers should wait for history reindex
  ([#3889](https://github.com/oasisprotocol/oasis-core/issues/3889))

  If a node first syncs consensus without any runtimes configured and a runtime
  is configured later, the workers should wait for historic runtime block
  reindexing to complete before continuing with initialization. Otherwise
  historic block queries may fail and prevent the worker from operating
  normally.

- go/consensus/tendermint: Update nonce post-execution during CheckTx
  ([#3896](https://github.com/oasisprotocol/oasis-core/issues/3896))

  This now correctly handles multiple transactions from the same signer being
  checked in the same block as previously subsequent transactions were
  rejected.

- worker/storage: Fix heartbeat stall
  ([#3899](https://github.com/oasisprotocol/oasis-core/issues/3899))

- go/runtime/client: Properly propagate CheckTx error context
  ([#3973](https://github.com/oasisprotocol/oasis-core/issues/3973))

### Documentation Improvements

- ADR 0008: Standard Account Key Generation
  ([#3656](https://github.com/oasisprotocol/oasis-core/issues/3656))

- Update [Security] document
  ([#3853](https://github.com/oasisprotocol/oasis-core/issues/3853))

  [Security]: SECURITY.md

- Note that `RELEASE_BRANCH` variable needs to be exported in [Release Process]
  ([#3891](https://github.com/oasisprotocol/oasis-core/issues/3891),
   [#3993](https://github.com/oasisprotocol/oasis-core/issues/3993))

  [Release Process]: docs/release-process.md

- ADR 0009: Ed25519 Signature Verification Semantics
  ([#3925](https://github.com/oasisprotocol/oasis-core/issues/3925))

- Add missing gRPC services and beacon service
  ([#3991](https://github.com/oasisprotocol/oasis-core/issues/3991))

### Internal Changes

- go/worker: Make compute and client node use local storage if available
  ([#3251](https://github.com/oasisprotocol/oasis-core/issues/3251))

- Runtime consensus state interoperability tests
  ([#3833](https://github.com/oasisprotocol/oasis-core/issues/3833))

- go: bump github.com/hashicorp/go-hclog from 0.15.0 to 0.16.1
  ([#3834](https://github.com/oasisprotocol/oasis-core/issues/3834),
  [#3927](https://github.com/oasisprotocol/oasis-core/issues/3927))

- go/storage: Remove unused ForceFinalize RPC call
  ([#3863](https://github.com/oasisprotocol/oasis-core/issues/3863))

- e2e/runtime: Add test for storage sync after messy/incorrect cleanup
  ([#3863](https://github.com/oasisprotocol/oasis-core/issues/3863))

- rust: bump tendermint from 0.18.1 to 0.19.0
  ([#3866](https://github.com/oasisprotocol/oasis-core/issues/3866))

- Build and upload release artifacts on every master/stable merge
  ([#3875](https://github.com/oasisprotocol/oasis-core/issues/3875))

- go: Ignore jwt-go vulns since we're not using the features
  ([#3877](https://github.com/oasisprotocol/oasis-core/issues/3877))

- go: bump github.com/hashicorp/go-plugin from 1.4.0 to 1.4.2
  ([#3880](https://github.com/oasisprotocol/oasis-core/issues/3880))

- Bump Go to 1.16.3
  ([#3886](https://github.com/oasisprotocol/oasis-core/issues/3886))

- changelog: Automatically add protocol versions table
  ([#3891](https://github.com/oasisprotocol/oasis-core/issues/3891))

- rust: bump hmac from 0.10.1 to 0.11.0
  ([#3906](https://github.com/oasisprotocol/oasis-core/issues/3906))

- go: bump github.com/grpc-ecosystem/go-grpc-middleware from 1.2.2 to 1.3.0
  ([#3915](https://github.com/oasisprotocol/oasis-core/issues/3915))

- go/staking/gen_account_vectors: Add [ADR 0008] test vectors
  ([#3918](https://github.com/oasisprotocol/oasis-core/issues/3918),
   [#3960](https://github.com/oasisprotocol/oasis-core/issues/3960))

  <!-- markdownlint-disable line-length -->
  [ADR 0008]:
    https://github.com/oasisprotocol/adrs/blob/main/0008-standard-account-key-generation.md
  <!-- markdownlint-enable line-length -->

- go: bump github.com/libp2p/go-libp2p from 0.13.0 to 0.14.0
  ([#3928](https://github.com/oasisprotocol/oasis-core/issues/3928))

- common/crypto/slip-10: Relax the seed-length check
  ([#3945](https://github.com/oasisprotocol/oasis-core/issues/3945))

  The SLIP-0010 spec, was updated after approximately 5 years to be
  coherent, so support `S` that range from 128-bits to 512-bits, and
  add in the formerly nonsensical test vector.

- runtime/common/crypto/signature: Switch Ed25519 to our consensus flavor
  ([#3946](https://github.com/oasisprotocol/oasis-core/issues/3946))

- rust: bump curve25519-dalek from 3.0.0 to 3.1.0
  ([#3949](https://github.com/oasisprotocol/oasis-core/issues/3949))

- runtime: Bump futures/tokio/grpcio
  ([#3950](https://github.com/oasisprotocol/oasis-core/issues/3950))

- go: bump github.com/prometheus/common from 0.20.0 to 0.25.0
  ([#3951](https://github.com/oasisprotocol/oasis-core/issues/3951))

- go: bump google.golang.org/grpc to 1.38.0
  ([#3953](https://github.com/oasisprotocol/oasis-core/issues/3953))

- Bump Rust toolchain to 2021-05-20
  ([#3955](https://github.com/oasisprotocol/oasis-core/issues/3955))

- workload/governance: fix case with multiple equal active proposals
  ([#3959](https://github.com/oasisprotocol/oasis-core/issues/3959))

- go/runtime/scheduling: priority queue txpool
  ([#3965](https://github.com/oasisprotocol/oasis-core/issues/3965))

  Priority queue transaction pool (based on B-Trees) is implemented to support
  scheduling based on the newly added runtime transaction priorities.

- go: bump github.com/uber/jaeger-client-go to 2.29.1+incompatible
  ([#3966](https://github.com/oasisprotocol/oasis-core/issues/3966))

- Bump grpcio to 0.9.0
  ([#3968](https://github.com/oasisprotocol/oasis-core/issues/3968))

- go/common/errors: Support context propagation
  ([#3973](https://github.com/oasisprotocol/oasis-core/issues/3973))

  This adds `WithContext` and `Context` in order to be able to add an error
  context in a structured way. Such contexts are then correctly propagated
  over gRPC and consensus layer transaction results in order to improve the
  error messages.

- rust: bump crossbeam from 0.8.0 to 0.8.1
  ([#3977](https://github.com/oasisprotocol/oasis-core/issues/3977))

- go: bump github.com/multiformats/go-multiaddr from 0.3.1 to 0.3.2
  ([#3978](https://github.com/oasisprotocol/oasis-core/issues/3978))

- go: bump github.com/cenkalti/backoff/v4 from 4.1.0 to 4.1.1
  ([#3979](https://github.com/oasisprotocol/oasis-core/issues/3979))

- go: bump github.com/libp2p/go-libp2p from 0.14.0 to 0.14.1
  ([#3980](https://github.com/oasisprotocol/oasis-core/issues/3980))

- rust/Cargo.toml: specify exact ring depedency version
  ([#3981](https://github.com/oasisprotocol/oasis-core/issues/3981))

- runtime: Stop using the ring backend for snow
  ([#3990](https://github.com/oasisprotocol/oasis-core/issues/3990))

- rust: use 0.0.0 as crate versions
  ([#3995](https://github.com/oasisprotocol/oasis-core/issues/3995))

  Crates are following [Oasis Core versioning scheme]. The crates are not
  published and GitHub tags should be used as version definitions. Therefore
  bumping versions on the crates themselves is omitted. Update crate authors.

  [oasis core versioning scheme]:
    /oasis-core/processes/versioning

- go/worker/common: Wait for all child workers to initialize
  ([#4001](https://github.com/oasisprotocol/oasis-core/issues/4001))

## 21.1 (2021-04-12)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 4.0.0     |
| Runtime Host      | 2.0.0     |
| Runtime Committee | 2.0.0     |

### Removals and Breaking Changes

- go/registry: Allow update from no key manager to with key manager
  ([#3802](https://github.com/oasisprotocol/oasis-core/issues/3802))

- go/common/entity: Rename `LatestEntityDescriptorVersion`
  ([#3845](https://github.com/oasisprotocol/oasis-core/issues/3845))

  Rename it to `LatestDescriptorVersion`.

- go/upgrade: Limit `Descriptor`'s field values
  ([#3845](https://github.com/oasisprotocol/oasis-core/issues/3845))

  Add variables defining `Descriptor`'s field value limits:
  `MinDescriptorVersion`, `MaxDescriptorVersion`, `MinUpgradeHandlerLength`,
  `MaxUpgradeHandlerLength`, `MinUpgradeEpoch`, `MaxUpgradeEpoch`.

- storage: Drop the MKVS node version field
  ([#3500](https://github.com/oasisprotocol/oasis-core/issues/3500))

- go/common/version: Move `ConsensusProtocol` ver to top of `ProtocolVersions`
  ([#3845](https://github.com/oasisprotocol/oasis-core/issues/3845))

### Features

- oasis-net-runner: Configure a client node even without runtimes
  ([#3794](https://github.com/oasisprotocol/oasis-core/issues/3794))

- go/staking: Improve pretty-print for `Escrow`/`ReclaimEscrow` transactions
  ([#3819](https://github.com/oasisprotocol/oasis-core/issues/3819))

- go/common/entity: Add `{Min,Max}DescriptorVersion` constants
  ([#3845](https://github.com/oasisprotocol/oasis-core/issues/3845))

- go/common/version: Add `ValidateBasic()` to `Version` and `ProtocolVersions`
  ([#3845](https://github.com/oasisprotocol/oasis-core/issues/3845))

- go/worker/compute/executor: Enable scheduler transaction checks by default
  ([#3851](https://github.com/oasisprotocol/oasis-core/issues/3851))

### Bug Fixes

- oasis-net-runner: Configure a runtime in default fixture
  ([#3805](https://github.com/oasisprotocol/oasis-core/issues/3805))

- go/worker/storage: Fix Finalize and Apply failure handling
  ([#3820](https://github.com/oasisprotocol/oasis-core/issues/3820))

- go/storage: Fix failure handling in checkpoint syncing
  ([#3830](https://github.com/oasisprotocol/oasis-core/issues/3830))

  In some cases, the database could be left in a corrupt state after a
  checkpoint chunk failed to be restored.

- go/consensus/tendermint: Bump Tendermint Core to v0.34.9-oasis2
  ([#3844](https://github.com/oasisprotocol/oasis-core/issues/3844))

### Internal Changes

- go: bump github.com/golang/protobuf from 1.4.3 to 1.5.1
  ([#3799](https://github.com/oasisprotocol/oasis-core/issues/3799))

- go: bump github.com/prometheus/client_golang from 1.9.0 to 1.10.0
  ([#3803](https://github.com/oasisprotocol/oasis-core/issues/3803))

- go: bump github.com/prometheus/common from 0.19.0 to 0.20.0
  ([#3811](https://github.com/oasisprotocol/oasis-core/issues/3811))

- go: bump google.golang.org/grpc from 1.36.0 to 1.36.1
  ([#3816](https://github.com/oasisprotocol/oasis-core/issues/3816))

- go/storage/client: Implement node blacklisting
  ([#3820](https://github.com/oasisprotocol/oasis-core/issues/3820))

- go/worker/storage: Add independent heartbeat for syncing retries
  ([#3820](https://github.com/oasisprotocol/oasis-core/issues/3820))

- go: bump github.com/golang/protobuf from 1.5.1 to 1.5.2
  ([#3821](https://github.com/oasisprotocol/oasis-core/issues/3821))

- go/worker/common: Iterate over all handlers on unhandled peer message
  ([#3838](https://github.com/oasisprotocol/oasis-core/issues/3838))

- go/runtime/client: Also recheck blocks periodically
  ([#3842](https://github.com/oasisprotocol/oasis-core/issues/3842))

- go/consensus/api/transaction/testvectors: Extend meaning of the `Valid` field
  ([#3845](https://github.com/oasisprotocol/oasis-core/issues/3845))

  Extend meaning of `TestVector`'s `Valid` field to also indicate that the
  given test vector's transaction passes basic static validation (besides having
  a valid signature and being correctly serialized).

  Update `MakeTestVector()` and `MakeTestVectorWithSigner()` functions to take
  the `valid` argument indicating whether the transaction is valid or not.

  Update go/registry/gen_vectors, go/staking/gen_vectors and
  go/governance/gen_vectors packages.

  Expand go/governance/gen_vectors package to cover more (invalid) transaction
  cases.

## 21.0 (2021-03-18)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 3.0.0     |
| Runtime Host      | 2.0.0     |
| Runtime Committee | 2.0.0     |

### Removals and Breaking Changes

- go/consensus/tendermint: Handle `LIGHT_CLIENT_ATTACK` evidence
  ([#3156](https://github.com/oasisprotocol/oasis-core/issues/3156))

- go/beacon: Add a PVSS based beacon backend
  ([#3180](https://github.com/oasisprotocol/oasis-core/issues/3180))

  This is a significant improvement over the existing beacon, in that it at
  least attempts to be secure.

  For more details, see [ADR 0007].

  <!-- markdownlint-disable line-length -->
  [ADR 0007]:
    https://github.com/oasisprotocol/adrs/blob/main/0007-improved-random-beacon.md
  <!-- markdownlint-enable line-length -->

- go: Use human readable identifiers for slashing reasons
  ([#3276](https://github.com/oasisprotocol/oasis-core/issues/3276),
   [#3646](https://github.com/oasisprotocol/oasis-core/issues/3646))

  When serialized into JSON the slashing reason identifiers are now human
  readable (e.g. `consensus-equivocation` instead of `0`).

  Old:

  ```json
  "slashing": {
      "0": {
          "amount": "100",
          "freeze_interval": 1
      }
  }
  ```

  New:

  ```json
  "slashing": {
      "consensus-equivocation": {
          "amount": "100",
          "freeze_interval": 1
      }
  }
  ```

- go: Improve error message when delegating less than `MinDelegationAmount`
  ([#3308](https://github.com/oasisprotocol/oasis-core/issues/3308))

  Previously, an `ErrInvalidArgument` was returned in this case, which
  is not very descriptive, so a separate error was created:
  `ErrUnderMinDelegationAmount`.

- go/worker/p2p: Include chain ID and remove patch version from topic IDs
  ([#3311](https://github.com/oasisprotocol/oasis-core/issues/3311))

- go: Move storage backend initialization to storage worker
  ([#3323](https://github.com/oasisprotocol/oasis-core/issues/3323))

  Notably, this also means that node command line options for storage
  configuration have been renamed and that the backend type option isn't
  needed anymore unless the storage worker is enabled.

- Compare protocol versions according to SemVer 2.0.0
  ([#3360](https://github.com/oasisprotocol/oasis-core/issues/3360))

  As described in our [Versioning] document, we bumped the protocol versions to
  version 1.0.0 with the release of [Oasis Core 20.10].

  Hence, we also need to modify how we compare and detect backward-incompatible
  changes to follow SemVer 2.0.0 rules.

  From now onwards, only a change in a protocol's major version signifies
  a backward-incompatible change.

  [Versioning]: docs/versioning.md#version-100
  [Oasis Core 20.10]:
    https://github.com/oasisprotocol/oasis-core/blob/v20.10/CHANGELOG.md

- go/common/version: Remove `MajorMinor()` method from `Version` type
  ([#3360](https://github.com/oasisprotocol/oasis-core/issues/3360))

- roothash: Add support for failure indicating commitments
  ([#3391](https://github.com/oasisprotocol/oasis-core/issues/3391))

  Failure-indicating executor commits are introduced in order to give the
  compute nodes a possibility to vote for failure when they cannot execute the
  given batch (e.g., due to unavailability of storage). Such commits will always
  trigger a discrepancy during discrepancy detection and will vote for failing
  the round in discrepancy resolution phase.

  For more details, see [ADR 0005].

  <!-- markdownlint-disable line-length -->
  [ADR 0005]:
    https://github.com/oasisprotocol/adrs/blob/main/0005-runtime-compute-slashing.md
  <!-- markdownlint-enable line-length -->

- Introduce storage root types
  ([#3415](https://github.com/oasisprotocol/oasis-core/issues/3415))

  Each storage root now has an associated type (i.e. IO or state). In
  particular, this impacts the Apply and ApplyBatch calls and also changes
  the storage format of the Badger NodeDB.

- go/staking: Add support for beneficiary allowances
  ([#3428](https://github.com/oasisprotocol/oasis-core/issues/3428))

  The staking service now supports setting allowances on general account
  balances as specified by [ADR 0003].

  <!-- markdownlint-disable line-length -->
  [ADR 0003]:
    https://github.com/oasisprotocol/adrs/blob/main/0003-consensus-runtime-token-transfer.md
  <!-- markdownlint-enable line-length -->

- Add runtime accounts in the consensus layer
  ([#3429](https://github.com/oasisprotocol/oasis-core/issues/3429))

  As described in [ADR 0003] this adds support for runtimes having accounts in
  the consensus layer. Runtimes can manipulate those accounts by emitting newly
  introduced transfer and withdraw runtime messages.

  <!-- markdownlint-disable line-length -->
  [ADR 0003]:
    https://github.com/oasisprotocol/adrs/blob/main/0003-consensus-runtime-token-transfer.md
  <!-- markdownlint-enable line-length -->

- go/roothash: Refactor runtime messages
  ([#3430](https://github.com/oasisprotocol/oasis-core/issues/3430))

  Several modifications are made to the runtime message representation and
  processing as specified by [ADR 0003].

  <!-- markdownlint-disable line-length -->
  [ADR 0003]:
    https://github.com/oasisprotocol/adrs/blob/main/0003-consensus-runtime-token-transfer.md
  <!-- markdownlint-enable line-length -->

- go/roothash: Renamed `FinalizedEvent` field in `roothash.Event`
  ([#3448](https://github.com/oasisprotocol/oasis-core/issues/3448))

  The `FinalizedEvent` field in the `roothash.Event` structure has been renamed
  to just `Finalized` in order to be consistent with other fields.

  Note that the serialization already used just `finalized` so that remains
  unchanged.

- Remove `SignedRuntime`
  ([#3450](https://github.com/oasisprotocol/oasis-core/issues/3450))

  As part of the work on [ADR 0004], support for signed runtime descriptors
  has been removed, since they are no longer required.
  All methods that used to take signed runtime descriptors now take
  non-signed runtime descriptors instead.

  This also affects the genesis file. Use the `oasis-node debug fix-genesis`
  command to convert a genesis file from the old format to the new one.

  [ADR 0004]:
    https://github.com/oasisprotocol/adrs/blob/main/0004-runtime-governance.md

- Modify runtime descriptors to support ADR 0004
  ([#3450](https://github.com/oasisprotocol/oasis-core/issues/3450))

  As described in [ADR 0004], the runtime descriptors are modified to
  enable runtime governance.

  [ADR 0004]:
    https://github.com/oasisprotocol/adrs/blob/main/0004-runtime-governance.md

- go/consensus/tendermint: Use canonical chain context in InitChain
  ([#3477](https://github.com/oasisprotocol/oasis-core/issues/3477))

- go/roothash/genesis: Restore state from suspended runtimes
  ([#3484](https://github.com/oasisprotocol/oasis-core/issues/3484))

  Roothash state of suspended runtimes in genesis was previously not correctly
  restored, causing the suspended runtime state to reset once the runtime was
  resumed.

- Implement Consensus Governance backend
  ([#3502](https://github.com/oasisprotocol/oasis-core/issues/3502))

  As described in [ADR 0006] this adds the consensus governance backend
  implementation.

  See [ADR 0006] and [Governance backend documentation] for more
  details.

  [ADR 0006]:
    https://github.com/oasisprotocol/adrs/blob/main/0006-consensus-governance.md
  [Governance backend documentation]: docs/consensus/services/governance.md

- runtime: Move consensus layer structures to its own module
  ([#3511](https://github.com/oasisprotocol/oasis-core/issues/3511))

  Everything under `common::{address, registry, roothash, staking}` in the
  `oasis-core-runtime` crate has been moved under the `consensus` module.

- go/consensus/api: Rename `ConsensusVersion` to `Version` in `Status` type
  ([#3511](https://github.com/oasisprotocol/oasis-core/issues/3511))

- go/upgrade: Support multiple pending upgrades
  ([#3536](https://github.com/oasisprotocol/oasis-core/issues/3536))

  Upgrade module now supports submitting multiple upgrades.

- go/registry/api: Allow updating more fields when updating an expired node
  ([#3539](https://github.com/oasisprotocol/oasis-core/issues/3539))

  Before, registering an expired (but not yet deleted) node was subject to the
  same update restrictions as an active node being updated.

- go/oasis-node/cmd/stake: Enhance `account info`'s output
  ([#3557](https://github.com/oasisprotocol/oasis-core/issues/3557))

  It now also displays an account's incoming and outgoing active/debonding
  delegations, total and available balance.

- go/consensus: Include consensus genesis parameters in `GetParameters`
  ([#3565](https://github.com/oasisprotocol/oasis-core/issues/3565))

  Consensus `GetParameters` method response now includes the consensus genesis
  parameters.

- runtime: Make `CheckTx` result more generic
  ([#3573](https://github.com/oasisprotocol/oasis-core/issues/3573))

  The previous definition made it hard for the runtime host to reason about the
  returned status code of `CheckTx` unless it was tied to the result format
  defined by the runtime.

  This is a breaking change to the Runtime Host Protocol as the
  `RuntimeCheckTxBatchResponse` structure has changed. It also breaks the
  `transaction::Dispatcher API`.

- go/upgrade: Use `ProtocolVersions` as internal upgrade identifier
  ([#3579](https://github.com/oasisprotocol/oasis-core/issues/3579))

  Before this change the internal upgrades used node binary hashes to ensure
  upgrade version compatibility. To make it more practical use software versions
  instead.

- Add ability to set a non-zero initial commission schedule
  ([#3601](https://github.com/oasisprotocol/oasis-core/issues/3601))

  When setting the initial commission schedule for an account, the
  `RateBoundLead` restriction is ignored. Therefore the initial bounds and rates
  can be set for the first next epoch aligned with `RateChangeInterval`.

  This effectively means that accounts without a configured commission schedule
  should be considered as having bounds: `0%-100%`, as the initial schedule can
  be set at any next epoch.

- go/scheduler: Check runtime versions for node eligibility
  ([#3611](https://github.com/oasisprotocol/oasis-core/issues/3611))

- go/roothash/api/message: Add `RegistryMessage` runtime message
  ([#3628](https://github.com/oasisprotocol/oasis-core/issues/3628))

  A new runtime message was added that enables runtimes to submit updated
  runtime descriptors for their runtime to the registry.

- runtime: Remove `common::runtime::RuntimeId`
  ([#3633](https://github.com/oasisprotocol/oasis-core/issues/3633))

  The Go API has been using `Namespace` for a while so this makes it
  consistent in the Rust runtime as well.

- go/roothash: Support slashing runtime compute nodes
  ([#3640](https://github.com/oasisprotocol/oasis-core/issues/3640))

  Runtimes can configure whether compute nodes should be slashed for submitting
  incorrect results or equivocating.

  For more details, see [ADR 0005].

  <!-- markdownlint-disable line-length -->
  [ADR 0005]:
    https://github.com/oasisprotocol/adrs/blob/main/0005-runtime-compute-slashing.md
  <!-- markdownlint-enable line-length -->

- runtimes: Support for `Add/ReclaimEscrow` runtime messages
  ([#3641](https://github.com/oasisprotocol/oasis-core/issues/3641))

  Escrow runtime messages need to be explicitly enabled via the
  `AllowEscrowMessages` consensus parameter.

- go/roothash: Runtime domain separation context in executor commitments
  ([#3643](https://github.com/oasisprotocol/oasis-core/issues/3643))

- Add runtime scheduling constraints
  ([#3644](https://github.com/oasisprotocol/oasis-core/issues/3644))

  Each runtime can now impose additional scheduling constraints for its
  committee nodes (separately for primary/backup):

  - Validator set membership.
  - Maximum number of nodes per entity.
  - Minimum candidate node pool size.

- go/slashing/api: Change `SlashReason` type to `uint8`
  ([#3646](https://github.com/oasisprotocol/oasis-core/issues/3646))

- go/staking/api: Rename `DoubleSigning` to `ConsensusEquivocation`
  ([#3646](https://github.com/oasisprotocol/oasis-core/issues/3646))

- go/registry: Fix node sanity checks
  ([#3660](https://github.com/oasisprotocol/oasis-core/issues/3660))

- Remove support for entity-signed node registrations
  ([#3661](https://github.com/oasisprotocol/oasis-core/issues/3661))

  Support for entity-signed node registrations has been removed,
  as they were only used in tests and not on any real network.
  Only node-signed node registrations are supported now.

- go/registry: Change minimum `ProposerTimeout` from 5 to 2 blocks
  ([#3682](https://github.com/oasisprotocol/oasis-core/issues/3682))

- go/genesis/api: Change canonical form of genesis file to end with a newline
  ([#3709](https://github.com/oasisprotocol/oasis-core/issues/3709))

- go/staking/state: Remove nonce as the debonding delegations disambiguator
  ([#3717](https://github.com/oasisprotocol/oasis-core/issues/3717))

  Account nonce is removed from the debonding delegations state key. Instead,
  if there are multiple debonding delegations for the same account and debond
  end epoch, those get merged into a single debonding delegation record.

- runtime: Introduce `RoundResults` to allow adding other information
  ([#3726](https://github.com/oasisprotocol/oasis-core/issues/3726))

  In addition to the existing runtime message execution results we want to
  provide additional information about the last successful round to runtimes.
  This introduces a `RoundResults` structure for this purpose.

- go/staking/api: Rename `Delegations()` method to `DelegationsFor()`
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

- go/staking/api: Rename `DebondingDelegations()` method
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

  Rename it to `DebondingDelegationsFor()`.

- go/upgrade/api: Version upgrade `Descriptor`
  ([#3781](https://github.com/oasisprotocol/oasis-core/issues/3781))

- go/consensus: Store runtime state roots in a single key
  ([#3782](https://github.com/oasisprotocol/oasis-core/issues/3782))

  That makes it easier to construct proofs starting at the consensus state root
  that prove what the state root of a specific runtime is. You can then chain
  these proofs to prove something about runtime state.

- go/staking/api/token: Print token's symbol after the amount
  ([#3784](https://github.com/oasisprotocol/oasis-core/issues/3784))

  This is more consistent with how others present token amounts.

- go/consensus/api/transaction: Print txn's method and body before the rest
  ([#3784](https://github.com/oasisprotocol/oasis-core/issues/3784))

  This is more intuitive and enables people to discover the transaction's main
  information quicker.

- go/consensus/tendermint: Bump Tendermint Core to v0.34.8-oasis1
  ([#3786](https://github.com/oasisprotocol/oasis-core/issues/3786))

- go/roothash: Finish commitment processing early when possible
  ([#3790](https://github.com/oasisprotocol/oasis-core/issues/3790))

  When the set of current commitments already determines the fate of the
  process (e.g., when there is a discrepancy or a majority of votes indicate
  success), proceed with the process instead of waiting for the remaining
  commitments.

- go/upgrade/api: Simplify upgrade `Descriptor`
  ([#3793](https://github.com/oasisprotocol/oasis-core/issues/3793))

  Remove `UpgradeMethod` type and `Method` field, rename `Name` field to
  `Handler` and replace `Identifier` field with `Target` field which corresponds
  to an upgrade's target version.

- go/common/version: Remove `Toolchain` field from `ProtocolVersions`
  ([#3793](https://github.com/oasisprotocol/oasis-core/issues/3793))

### Configuration Changes

- go: Change storage backend configuration options
  ([#3323](https://github.com/oasisprotocol/oasis-core/issues/3323))

  All the `--storage.*` options have been renamed to `--worker.storage.*`.

  Nodes that don't have the storage worker enabled don't need to configure
  the storage backend anymore, since it will be chosen correctly
  automatically.

- Change compute worker runtime configuration flags
  ([#3653](https://github.com/oasisprotocol/oasis-core/issues/3653))

  All the flags under `worker.runtime.*` have been moved under just
  `runtime.*`.

  For example the `worker.runtime.paths` flag needs to be renamed
  to `runtime.paths`.

### Features

- go/common/version: Add `MaskNonMajor()` method to `Version` type
  ([#3360](https://github.com/oasisprotocol/oasis-core/issues/3360))

- go/worker/storage: Add validation for IO roots in `Apply` operations
  ([#3440](https://github.com/oasisprotocol/oasis-core/issues/3440))

- go/runtime/client: Add `SubmitTxNoWait` method
  ([#3444](https://github.com/oasisprotocol/oasis-core/issues/3444))

  `SubmitTxNoWait` method publishes the runtime transaction and doesn't wait
  for results.

- Runtime client should fail `SubmitTx` calls until consensus is synced
  ([#3452](https://github.com/oasisprotocol/oasis-core/issues/3452))

- Runtime storage sync should use any storage node
  ([#3454](https://github.com/oasisprotocol/oasis-core/issues/3454))

  Before, storage node sync only used nodes from the current storage committee.
  Now it also syncs (with lower priority) from other storage nodes registered
  for the runtime.

- go/oasis-node/cmd: Add `oasis-node stake account validate_address` CLI command
  ([#3493](https://github.com/oasisprotocol/oasis-core/issues/3493),
   [#3589](https://github.com/oasisprotocol/oasis-core/issues/3589))

  It can be used to validate a staking account's address.

- runtime: Add `mkvs::Iterator` trait and `MKVS::iter` trait method
  ([#3499](https://github.com/oasisprotocol/oasis-core/issues/3499))

- runtime: Add `mkvs::OverlayTree` similar to its Go counterpart
  ([#3499](https://github.com/oasisprotocol/oasis-core/issues/3499))

- go/storage/mkvs: Generate proofs even if `Tree.Position` is not found
  ([#3499](https://github.com/oasisprotocol/oasis-core/issues/3499))

- go/consensus/api: Add `Registry()`/`Staking()`/`Scheduler()` to client backend
  ([#3511](https://github.com/oasisprotocol/oasis-core/issues/3511))

  This makes it more convenient to use the consensus client backend.

- go/oasis-node/cmd/stake: Add commands for managing allowances
  ([#3511](https://github.com/oasisprotocol/oasis-core/issues/3511))

  Add `oasis-node stake account gen_allow` and
  `oasis-node stake account gen_withdraw` CLI commands.

- go/consensus/tendermint: Also dump state when shutting down for upgrade
  ([#3516](https://github.com/oasisprotocol/oasis-core/issues/3516))

- go/common/version: Add `ConvertGoModulesVersion()` function
  ([#3546](https://github.com/oasisprotocol/oasis-core/issues/3546))

  It can be used to convert a Go Modules compatible version defined in
  [ADR 0002] (i.e. a Go Modules compatible Git tag without the `go/` prefix) to
  the canonical Oasis Core version.

  <!-- markdownlint-disable line-length -->
  [ADR 0002]:
    https://github.com/oasisprotocol/adrs/blob/main/0002-go-modules-compatible-git-tags.md
  <!-- markdownlint-enable line-length -->

- go/oasis-node/cmd: Add `oasis-node stake account nonce` CLI command
  ([#3559](https://github.com/oasisprotocol/oasis-core/issues/3559))

  It can be used to get a staking account's current nonce.

- go/scheduler: Add `ConsensusParameters` method to scheduler backend
  ([#3565](https://github.com/oasisprotocol/oasis-core/issues/3565))

- go/epochtime: Add `ConsensusParameters` method to epochtime backend
  ([#3565](https://github.com/oasisprotocol/oasis-core/issues/3565))

- runtime/common/version: Make `Version::new` a `const` function
  ([#3573](https://github.com/oasisprotocol/oasis-core/issues/3573))

  Also expose members publicly.

- go/runtime/client: Add `GetEvents` to fetch emitted runtime events
  ([#3573](https://github.com/oasisprotocol/oasis-core/issues/3573))

- go/worker/executor: Propose a new batch if there are message results
  ([#3645](https://github.com/oasisprotocol/oasis-core/issues/3645))

  The runtime executor now proposes a new batch if there are message results
  from previous round even if there are no transactions.

- go/runtime/client: Perform local `CheckTx` when a hosted runtime exists
  ([#3653](https://github.com/oasisprotocol/oasis-core/issues/3653))

- runtime: Add support for runtime-specific queries
  ([#3662](https://github.com/oasisprotocol/oasis-core/issues/3662))

  Runtimes can now implement a handler for `RuntimeQueryRequest` messages to
  expose arbitrary queries to runtime clients. Query routing is performed using
  method names.

- go/runtime/client: Also expose `CheckTx`
  ([#3662](https://github.com/oasisprotocol/oasis-core/issues/3662))

  The `CheckTx` functionality is now also exposed via the runtime client API.

- go/worker/storage: Add `StorageRPC` role and change access policy
  ([#3696](https://github.com/oasisprotocol/oasis-core/issues/3696))

  Getting checkpoints and diffs is now allowed for any connecting node,
  which eliminates a race condition and initialization difficulty in the
  storage committee node startup.

  State access is made gated but optionally public as before, depending on the
  value of the `worker.storage.public_rpc.enabled` configuration option.

- go/common/diff: Add package implementing helpers for comparing objects
  ([#3709](https://github.com/oasisprotocol/oasis-core/issues/3709))

  Add `UnifiedDiffString()` which returns unified diff between two strings.

- go/genesis/api: Update `WriteFileJSON()` to create files in the canonical form
  ([#3709](https://github.com/oasisprotocol/oasis-core/issues/3709))

  Consequentially, all its users (most notably the dump genesis halt hook) now
  produce genesis files in the canonical form.

- go/genesis/api: Add `CanonicalJSON()` method to `Document` type
  ([#3709](https://github.com/oasisprotocol/oasis-core/issues/3709))

  It can be used to obtain the canonical form of the genesis document
  serialized into a file.

- go/staking/api/token: Generalize `PrettyPrintAmount()`
  ([#3725](https://github.com/oasisprotocol/oasis-core/issues/3725))

  Support passing the amount as either `quantity.Quantity` or
  `prettyprint.Quantity`.

- go/staking/api: Add `StakeForShares()` method to `SharePool` type
  ([#3725](https://github.com/oasisprotocol/oasis-core/issues/3725))

  It can be used to compute the amount of base units for the given amount of
  shares.

- go/common/prettyprint: Add `Quantity` type
  ([#3725](https://github.com/oasisprotocol/oasis-core/issues/3725))

- runtime: Provide sets of good and bad compute nodes in round results
  ([#3726](https://github.com/oasisprotocol/oasis-core/issues/3726))

- go/control/GetStatus: Include the latest epoch
  ([#3743](https://github.com/oasisprotocol/oasis-core/issues/3743))

- go/runtime/registry: Add methods returning active runtime descriptors
  ([#3771](https://github.com/oasisprotocol/oasis-core/issues/3771))

  Runtime registry now includes methods returning the currently active runtime
  descriptor. Active descriptor is the runtime descriptor valid for the current
  epoch.

- go/beacon: Add `GetFutureEpoch` method to beacon API
  ([#3773](https://github.com/oasisprotocol/oasis-core/issues/3773))

- go/consensus/tendermint/apps/staking/state: Add incoming delegation methods
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

  Add new methods to `ImmutableState` type for querying incoming (debonding)
  delegations to an escrow account: `DelegationsTo()` and
  `DebondingDelegationsTo()`.

- go/staking/api: Add `DelegationsTo()`/`DebondingDelegationsTo()` methods
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

  They can be used to obtain all incoming (debonding) delegations to the given
  account.

- go/staking/api: Add `DelegationInfo` and `DebondingDelegationInfo` types
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

  They are (debonding) delegation descriptors with additional information about
  the share pool they belong to.

- go/staking/api: Add `DelegationInfosFor()`/`DebondingDelegationInfosFor()`
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

  They can be used to obtain incoming (debonding) delegations with additional
  information for the given account.

- runtime: Provide consensus layer chain domain separation context
  ([#3778](https://github.com/oasisprotocol/oasis-core/issues/3778))

  This adds a way for the runtime to be informed about the chain domain
  separation context that the consensus layer is using. It can be used by the
  runtime to perform domain separation for cryptographic signatures.

- go/consensus: Add `GetChainContext`
  ([#3778](https://github.com/oasisprotocol/oasis-core/issues/3778))

  This makes it easier for clients to fetch the chain domain separation context
  as previously they needed to fetch the genesis document and compute the chain
  context from it. It also adds ChainContext to the node's consensus status
  report.

- go/staking/api/token: Add support for passing token's value sign via context
  ([#3780](https://github.com/oasisprotocol/oasis-core/issues/3780))

- go/control/api: Add node status to registration status response
  ([#3783](https://github.com/oasisprotocol/oasis-core/issues/3783))

- go/oasis-node/cmd: Improve transaction preview when generating transactions
  ([#3792](https://github.com/oasisprotocol/oasis-core/issues/3792))

  Display amounts in tokens and display genesis document's hash when previewing
  transactions with various `oasis-node * gen_*` CLI commands.

- go/oasis-node/cmd/common/context: Add `GetCtxWithGenesisInfo()` helper
  ([#3792](https://github.com/oasisprotocol/oasis-core/issues/3792))

- go/upgrade: Implement `PrettyPrint` interface for `Descriptor`
  ([#3800](https://github.com/oasisprotocol/oasis-core/issues/3800))

- go/governance: Implement `PrettyPrint` interface for various types
  ([#3800](https://github.com/oasisprotocol/oasis-core/issues/3800))

  Implement `PrettyPrinter` for `ProposalContent`, `UpgradeProposal`,
  `CancelUpgradeProposal` and `ProposalVote` types.

- go/common/version: Implement `PrettyPrint` interface for `ProtocolVersions`
  ([#3800](https://github.com/oasisprotocol/oasis-core/issues/3800))

### Bug Fixes

- go/consensus: Include only top K validators at genesis time
  ([#3177](https://github.com/oasisprotocol/oasis-core/issues/3177))

  Previously, all the eligible validators were included in the validator set at
  genesis time.

  This has been fixed to include only the top `MaxValidators` as specified in
  the scheduler consensus parameters.

  Additionally, the `MaxValidatorsPerEntity` scheduler consensus parameter is
  now enforced.

- go/genesis: Fix epoch-based sanity checks
  ([#3477](https://github.com/oasisprotocol/oasis-core/issues/3477))

- go/storage/mkvs/checkpoint: Fix handling of non-zero earliest version
  ([#3480](https://github.com/oasisprotocol/oasis-core/issues/3480))

- go/consensus/tendermint: Fix early `GetStatus()` with initial height > 1
  ([#3481](https://github.com/oasisprotocol/oasis-core/issues/3481))

- go: Add missing size checks to `UnmarshalBinary()` methods
  ([#3497](https://github.com/oasisprotocol/oasis-core/issues/3497))

  Note that in practice these will never currently be triggered as the
  caller always checks the overall size before calling the more specific
  `UnmarshalBinary()` method.

- go/storage/mkvs: Fix edge case in overlay iterator
  ([#3499](https://github.com/oasisprotocol/oasis-core/issues/3499))

- runtime: Remove incorrect `Sync` impl on `mkvs::Tree`
  ([#3499](https://github.com/oasisprotocol/oasis-core/issues/3499))

- go/oasis-node/cmd/registry/entity: Reuse signer instead of creating a new one
  ([#3505](https://github.com/oasisprotocol/oasis-core/issues/3505))

  The `oasis-node registry entity register` CLI command previously always
  created two signer factories, one for signing the entity descriptor and one
  for signing the entity registration transaction.

  Some signers assign exclusive access to an underlying resource (e.g., HSM) to
  the given factory. In that case, all operations on the second signer factory
  would fail.

- Bump Go to 1.15.5
  ([#3512](https://github.com/oasisprotocol/oasis-core/issues/3512))

  This fixes a recently disclosed security vulnerability in the Go runtime
  library.

- go/worker/registration: Fix `RequestShutdown` for nodes with no registration
  ([#3524](https://github.com/oasisprotocol/oasis-core/issues/3524))

  In cases where the registration worker was started with a dummy
  goroutine that just waits for the service to stop, deregistration
  requests would hang, because the dummy wasn't watching the
  deregistration channel.

- go/worker/storage: Fill in additional versions when restoring state
  ([#3525](https://github.com/oasisprotocol/oasis-core/issues/3525))

  When a storage database from one network is used in a new network (e.g. when
  the consensus layer did a dump/restore upgrade) properly handle the case
  where there were additional rounds after the runtime has stopped (e.g., due
  to epoch transitions).

- go/consensus/tendermint: Report peers and validator status only after started
  ([#3534](https://github.com/oasisprotocol/oasis-core/issues/3534))

  When accessing the node status in very early stages of initialization when a
  Tendermint node structure is not available, the status RPC would make the node
  panic. Leave the peers and validator status blank instead.

- go/worker/storage: Force checkpoint sync when replication is needed
  ([#3538](https://github.com/oasisprotocol/oasis-core/issues/3538))

  Previously a freshly initialized storage node with no genesis state would
  fall back to incremental sync even though there was no chance of that
  succeeding.

- go/roothash/api/commitment: Return proposer commit in DR
  ([#3545](https://github.com/oasisprotocol/oasis-core/issues/3545))

  A subtle bug introduced in [#3448] and discovered by daily long-term tests.

  [#3448]: https://github.com/oasisprotocol/oasis-core/issues/3448

- go/tendermint: Fix `GetLightBlock`,`GetParameters` queries for latest height
  ([#3565](https://github.com/oasisprotocol/oasis-core/issues/3565))

- go/runtime/scheduling: Consumer should pull from scheduler
  ([#3569](https://github.com/oasisprotocol/oasis-core/issues/3569))

  Previously the scheduler would push batches to the consumer (e.g. compute
  node) which makes no sense as the consumer knows when it's ready to accept
  new batches. This changes the model so that the consumer pulls batches from
  the scheduler.

- go/consensus/tendermint/roothash: Fix latest block reindexing
  ([#3594](https://github.com/oasisprotocol/oasis-core/issues/3594))

  Only commit the block in case it was not already committed during reindex.
  This can happen when reindexing after a crash (e.g., the `before_index` crash
  point) since the initial height at which the reindex happens does not
  necessarily contain a round finalization event so reindexing up to height-1
  doesn't help.

  Discovered during long-term tests.

- go/worker/common/committee: Wait for initial consensus sync
  ([#3599](https://github.com/oasisprotocol/oasis-core/issues/3599))

- go/consensus/tendermint: Fix `nil` dereference in `EstimateGas`
  ([#3648](https://github.com/oasisprotocol/oasis-core/issues/3648))

- go/oasis-node/cmd/node: Fix error handling when writing in `dumpGenesis()`
  ([#3714](https://github.com/oasisprotocol/oasis-core/issues/3714))

- go/cmd/fixgenesis: Add default beacon and governance parameters
  ([#3728](https://github.com/oasisprotocol/oasis-core/issues/3728))

- go/consensus: Move upgrade logic to governance, gracefully handle halt
  ([#3755](https://github.com/oasisprotocol/oasis-core/issues/3755))

- go/consensus: Exclude expired nodes from validator set at genesis time
  ([#3763](https://github.com/oasisprotocol/oasis-core/issues/3763))

  The validator set selection algorithm now properly ignores expired nodes.

- go/upgrade: Ensure upgrade handler exists
  ([#3768](https://github.com/oasisprotocol/oasis-core/issues/3768))

- Allow switching binary while an upgrade is pending or in progress
  ([#3768](https://github.com/oasisprotocol/oasis-core/issues/3768))

  Removes `RunningVersion`/`SubmittingVersion` internal pending upgrade fields.
  Binary can now be switched mid-upgrade as long as it remains compatible with
  the in-progress upgrade.

- Progress the startup upgrade stage only after a successful startup step
  ([#3768](https://github.com/oasisprotocol/oasis-core/issues/3768))

  Before, the startup state was progressed before the startup stage was run,
  therefore in case of a failed startup upgrade the stage would be skipped after
  the node restart.

- runtime/scheduling: Fix `ordered_map.UpdateConfig`
  ([#3771](https://github.com/oasisprotocol/oasis-core/issues/3771))

  Before, `UpdateConfig` did not correctly update the list element reference
  causing an inconsistency of the underlying map and queue.

- go/roothash/reindexBlocks: Return latest known round if no new rounds indexed
  ([#3791](https://github.com/oasisprotocol/oasis-core/issues/3791))

  This fixes a case where a storage node would not register if restarted while
  synced and there were no new runtime rounds (e.g. the runtime is suspended).

- go/worker/executor: Avoid holding lock while applying processed batch
  ([#3801](https://github.com/oasisprotocol/oasis-core/issues/3801))

  Before, the executor worker would hold the `CrossNode` lock, while doing
  requests to storage.

### Documentation Improvements

- ADR 0003: Consensus/Runtime Token Transfer
  ([#3262](https://github.com/oasisprotocol/oasis-core/issues/3262))

- ADR 0004: Runtime Governance
  ([#3284](https://github.com/oasisprotocol/oasis-core/issues/3284))

- Document [genesis document's hash]
  ([#3312](https://github.com/oasisprotocol/oasis-core/issues/3312))

  [genesis document's hash]: docs/consensus/genesis.md#genesis-documents-hash

- Update [Release Process] documentation
  ([#3327](https://github.com/oasisprotocol/oasis-core/issues/3327))

  [Release Process]: docs/release-process.md

- ADR 0005: Runtime Compute Node Slashing
  ([#3339](https://github.com/oasisprotocol/oasis-core/issues/3339))

- Rename Versioning scheme document to Versioning and include it in the index
  ([#3360](https://github.com/oasisprotocol/oasis-core/issues/3360))

- docs: Fix some links that break with gitbook
  ([#3389](https://github.com/oasisprotocol/oasis-core/issues/3389))

- ADR 0006: Consensus Governance
  ([#3423](https://github.com/oasisprotocol/oasis-core/issues/3423))

- ADR 0007: Improved Random Beacon
  ([#3439](https://github.com/oasisprotocol/oasis-core/issues/3439))

- Update Deploying a Runtime document's example
  ([#3789](https://github.com/oasisprotocol/oasis-core/issues/3789))

### Internal Changes

- ci: Setup daily longterm tests with longer epoch periods
  ([#3301](https://github.com/oasisprotocol/oasis-core/issues/3301))

- Omit node operator link from release notes
  ([#3313](https://github.com/oasisprotocol/oasis-core/issues/3313))

- go: Bump github.com/prometheus/procfs from 0.1.3 to 0.3.0
  ([#3314](https://github.com/oasisprotocol/oasis-core/issues/3314),
   [#3616](https://github.com/oasisprotocol/oasis-core/issues/3616))

- Make: Output messages to stderr instead of stdout
  ([#3327](https://github.com/oasisprotocol/oasis-core/issues/3327))

- Make: Refactor Change Log handling
  ([#3327](https://github.com/oasisprotocol/oasis-core/issues/3327))

- internal: Refactor project's version handling
  ([#3327](https://github.com/oasisprotocol/oasis-core/issues/3327),
   [#3345](https://github.com/oasisprotocol/oasis-core/issues/3345),
   [#3492](https://github.com/oasisprotocol/oasis-core/issues/3492))

  Simplify version computation logic in Make files and start using Punch's
  version file to track version.

- Make: Refactor release-related targets
  ([#3327](https://github.com/oasisprotocol/oasis-core/issues/3327),
   [#3368](https://github.com/oasisprotocol/oasis-core/issues/3368))

  - Rename `tag-next-release` target to `release-tag`.
  - Rename `release` target to `release-build`.
  - Add `release-stable-branch` target that creates and pushes a stable branch
    for the current release.

- github: Bump GoReleaser in ci-reproducibility and release workflows to 0.152.0
  ([#3327](https://github.com/oasisprotocol/oasis-core/issues/3327),
   [#3368](https://github.com/oasisprotocol/oasis-core/issues/3368),
   [#3602](https://github.com/oasisprotocol/oasis-core/issues/3602))

- go/e2e/workload-queries: Allow historical `QueryTxs` to fail few times
  ([#3338](https://github.com/oasisprotocol/oasis-core/issues/3338))

- go/nancy: Remove `golang.org/x/net` false positive ignores
  ([#3340](https://github.com/oasisprotocol/oasis-core/issues/3340))

- go/dependencies/etcd: Update etcd with replace directive
  ([#3341](https://github.com/oasisprotocol/oasis-core/issues/3341))

- ci: Bump actions/setup-python from v2.1.2 to v2.2.1
  ([#3349](https://github.com/oasisprotocol/oasis-core/issues/3349),
   [#3405](https://github.com/oasisprotocol/oasis-core/issues/3405),
   [#3582](https://github.com/oasisprotocol/oasis-core/issues/3582))

- rust: Bump base64 from 0.12.3 to 0.13.0
  ([#3353](https://github.com/oasisprotocol/oasis-core/issues/3353))

- Prioritize nodes that signed storage receipts
  ([#3354](https://github.com/oasisprotocol/oasis-core/issues/3354))

  The compute executor and tag indexer now prioritize reads from storage nodes
  that signed the corresponding storage receipts.

- go/storage: Support node prioritization in read requests
  ([#3354](https://github.com/oasisprotocol/oasis-core/issues/3354))

  The following new functions are added to the storage API package to help
  storage backend implementations:

  - `WithNodePriorityHint`
  - `WithNodePriorityHintFromSignatures`
  - `NodePriorityHintFromContext`

- ci: Bump actions/setup-node from v2.1.1 to v2.1.4
  ([#3364](https://github.com/oasisprotocol/oasis-core/issues/3364),
   [#3563](https://github.com/oasisprotocol/oasis-core/issues/3563),
   [#3575](https://github.com/oasisprotocol/oasis-core/issues/3575))

- ci: Bump actions/setup-go from v2.1.2 to v2.1.3
  ([#3365](https://github.com/oasisprotocol/oasis-core/issues/3365))

- ci: Bump actions/upload-artifact from v2.1.4 to v2.2.2
  ([#3367](https://github.com/oasisprotocol/oasis-core/issues/3367),
   [#3520](https://github.com/oasisprotocol/oasis-core/issues/3520),
   [#3596](https://github.com/oasisprotocol/oasis-core/issues/3596))

- go/oasis-test-runner: Fix `e2e/consensus-state-sync` scenario (take two)
  ([#3369](https://github.com/oasisprotocol/oasis-core/issues/3369))

  Previous "fix" actually made the test silently skip actually performing state
  sync because it used the wrong validator index.

- go/e2e/queries: Correctly ignore `UnexpectedEOF` errors
  ([#3372](https://github.com/oasisprotocol/oasis-core/issues/3372))

- ci: Make build-fuzz failures fatal now that upstream is fixed
  ([#3374](https://github.com/oasisprotocol/oasis-core/issues/3374))

- go: Bump github.com/blevesearch/bleve from 1.0.10 to 1.0.14
  ([#3384](https://github.com/oasisprotocol/oasis-core/issues/3384),
   [#3530](https://github.com/oasisprotocol/oasis-core/issues/3530),
   [#3558](https://github.com/oasisprotocol/oasis-core/issues/3558))

- ci: Daily long-term test minor fixes
  ([#3387](https://github.com/oasisprotocol/oasis-core/issues/3387))

  - Don't fail on `UnexpectedEOF` during `GetTransactionsWithResults`.

  - Enable `"RecoverCorruptedWAL"` for all nodes.

- go/roothash: Add consistent hash test for `ComputeResultsHeader`
  ([#3391](https://github.com/oasisprotocol/oasis-core/issues/3391))

- go: Bump github.com/libp2p/go-libp2p-pubsub from 0.3.5 to 0.4.1
  ([#3392](https://github.com/oasisprotocol/oasis-core/issues/3392),
   [#3510](https://github.com/oasisprotocol/oasis-core/issues/3510),
   [#3624](https://github.com/oasisprotocol/oasis-core/issues/3624))

- go/e2e/runtime/runtime-upgrade: Wait for old compute nodes to expire
  ([#3404](https://github.com/oasisprotocol/oasis-core/issues/3404))

- go: Bump github.com/golang/protobuf from 1.4.2 to 1.4.3
  ([#3408](https://github.com/oasisprotocol/oasis-core/issues/3408))

- go/e2e: Add storage byzantine E2E test cases
  ([#3414](https://github.com/oasisprotocol/oasis-core/issues/3414))

- go: Bump github.com/prometheus/client_golang from 1.7.1 to 1.9.0
  ([#3419](https://github.com/oasisprotocol/oasis-core/issues/3419),
   [#3576](https://github.com/oasisprotocol/oasis-core/issues/3576))

- go: Bump github.com/spf13/cobra from 1.0.0 to 1.1.1
  ([#3427](https://github.com/oasisprotocol/oasis-core/issues/3427))

- go: Bump google.golang.org/grpc from 1.32.0 to 1.36.0
  ([#3437](https://github.com/oasisprotocol/oasis-core/issues/3437),
   [#3495](https://github.com/oasisprotocol/oasis-core/issues/3495),
   [#3543](https://github.com/oasisprotocol/oasis-core/issues/3543),
   [#3617](https://github.com/oasisprotocol/oasis-core/issues/3617),
   [#3631](https://github.com/oasisprotocol/oasis-core/issues/3631),
   [#3730](https://github.com/oasisprotocol/oasis-core/issues/3730))

- rust: Bump rustracing
  ([#3446](https://github.com/oasisprotocol/oasis-core/issues/3446))

  - Bump `rustracing` from 0.4.0 to 0.5.0.
  - Bump `rustracing_jaeger` from 0.5.0 to 0.6.0.

- go/consensus/tendermint: Remove `ForeignExecuteTx`
  ([#3448](https://github.com/oasisprotocol/oasis-core/issues/3448))

  Use recently introduced message passing between apps instead.

- go/consensus/tendermint: Add message passing between mux applications
  ([#3448](https://github.com/oasisprotocol/oasis-core/issues/3448))

- go/common/crash: Improvements to the debug crash framework
  ([#3449](https://github.com/oasisprotocol/oasis-core/issues/3449))

  - Threadsafe global crasher.
  - Ability to configure default probability for all crash points.
  - Fix reported caller information on crash.
  - Crash with a specific exit code.

- Add `GetEntityNodes()` query to registry state
  ([#3450](https://github.com/oasisprotocol/oasis-core/issues/3450))

- go: Bump github.com/hashicorp/go-plugin from 1.3.0 to 1.4.0
  ([#3494](https://github.com/oasisprotocol/oasis-core/issues/3494))

- go: Bump github.com/hashicorp/go-hclog from 0.14.1 to 0.15.0
  ([#3496](https://github.com/oasisprotocol/oasis-core/issues/3496))

- go/oasis-node/cmd/common/consensus: Augment `SignAndSaveTx()` with `signer`
  ([#3506](https://github.com/oasisprotocol/oasis-core/issues/3506))

  Add ability to pass a pre-existing `signature.Signer` as `signer` parameter to
  the `SignAndSaveTx()` function.

- go: Bump github.com/libp2p/go-libp2p-core from 0.6.1 to 0.8.5
  ([#3510](https://github.com/oasisprotocol/oasis-core/issues/3510),
   [#3711](https://github.com/oasisprotocol/oasis-core/issues/3711),
   [#3718](https://github.com/oasisprotocol/oasis-core/issues/3718))

- go: Bump github.com/libp2p/go-libp2p from 0.11.0 to 0.13.0
  ([#3510](https://github.com/oasisprotocol/oasis-core/issues/3510),
   [#3588](https://github.com/oasisprotocol/oasis-core/issues/3588))

- rust: Bump arc-swap to 0.4.8
  ([#3511](https://github.com/oasisprotocol/oasis-core/issues/3511))

- ci: Bump actions/download-artifact from v2.0.5 to v2.0.8
  ([#3519](https://github.com/oasisprotocol/oasis-core/issues/3519),
   [#3571](https://github.com/oasisprotocol/oasis-core/issues/3571),
   [#3597](https://github.com/oasisprotocol/oasis-core/issues/3597))

- github: Replace deprecated `set-env` workflow command with environment file
  ([#3522](https://github.com/oasisprotocol/oasis-core/issues/3522))

- go/storage/mkvs/checkpoint: Add initial version parameter
  ([#3538](https://github.com/oasisprotocol/oasis-core/issues/3538))

  Previously, if the local database contained a version earlier than the genesis
  version, the checkpointer would attempt to create a new checkpoint at that
  earlier version (and fail). Now the version is clamped at the initial
  version.

- ci: Bump docker/build-push-action from v1 to v2.2.2
  ([#3549](https://github.com/oasisprotocol/oasis-core/issues/3549),
   [#3605](https://github.com/oasisprotocol/oasis-core/issues/3605))

- go/oasis-node/cmd/common: Add `LoadEntitySigner()` helper
  ([#3556](https://github.com/oasisprotocol/oasis-core/issues/3556))

  Replace `LoadEntity()` helper with `LoadEntitySigner()` that requires no
  arguments and loads the entity directory and obtains the signer backend by
  itself.

- go/oasis-node/txsource: Increase submission timeout
  ([#3568](https://github.com/oasisprotocol/oasis-core/issues/3568))

  Sometimes it can take up to two minutes for a transaction to get included in a
  block due to high load.

- dependencies: Update bubblewrap to 0.4.1
  ([#3577](https://github.com/oasisprotocol/oasis-core/issues/3577))

- go/oasis-node/txsource: Fix event validation in queries workload
  ([#3593](https://github.com/oasisprotocol/oasis-core/issues/3593))

  A single transaction can now emit multiple identical events when performing
  runtime message execution emitting events.

- go/e2e/txsource: Add txsource SGX scenario using fewer nodes
  ([#3595](https://github.com/oasisprotocol/oasis-core/issues/3595))

- go/oasis-test-runner/txsource: Add governance workload
  ([#3603](https://github.com/oasisprotocol/oasis-core/issues/3603))

- rust: Bump smallvec to 0.6.14
  ([#3604](https://github.com/oasisprotocol/oasis-core/issues/3604))

- runtime/storage/mkvs: Add MKVS impl for `&mut T`
  ([#3604](https://github.com/oasisprotocol/oasis-core/issues/3604))

- go/e2e/governance-upgrade: Wait for compute nodes to be ready
  ([#3618](https://github.com/oasisprotocol/oasis-core/issues/3618))

- rust: Bump honggfuzz from 0.5.51 to 0.5.52
  ([#3621](https://github.com/oasisprotocol/oasis-core/issues/3621))

- rust: Bump slog-scope from 4.3.0 to 4.4.0
  ([#3622](https://github.com/oasisprotocol/oasis-core/issues/3622))

- go/common/cbor: Re-export `Marshaler` and `Unmarshaler` interfaces
  ([#3630](https://github.com/oasisprotocol/oasis-core/issues/3630))

- go: Bump github.com/stretchr/testify from 1.6.1 to 1.7.0
  ([#3632](https://github.com/oasisprotocol/oasis-core/issues/3632))

- runtime: Validate block namespace against runtime ID
  ([#3633](https://github.com/oasisprotocol/oasis-core/issues/3633))

- go/oasis-test-runner/txsource: Decrease `MinPoolSize` for restarts
  ([#3636](https://github.com/oasisprotocol/oasis-core/issues/3636))

  When restarts are enabled there can be one less node so we should make sure
  to decrease the `MinPoolSize` in this case.

- go/runtime: Move host configuration to runtime registry
  ([#3653](https://github.com/oasisprotocol/oasis-core/issues/3653))

- go/runtime/host: Add helpers for common requests
  ([#3653](https://github.com/oasisprotocol/oasis-core/issues/3653))

  An additional interface `RichRuntime` is added which provides wrappers for
  common requests (currently only `CheckTx`).

- go: Bump ed25519 for fixes on 32-bit architectures
  ([#3657](https://github.com/oasisprotocol/oasis-core/issues/3657))

  Note that 32-bit architectures are not supported by Oasis Core.

- runtime: Refactor the dispatcher
  ([#3662](https://github.com/oasisprotocol/oasis-core/issues/3662))

  Previously, each request handler performed its own response submission which
  repeated a lot of code. This has now been changed by all handlers returning
  a proper result type and the main dispatch loop sending the responses.

- tests: Fix potential key clash in the confidential test KV runtime
  ([#3663](https://github.com/oasisprotocol/oasis-core/issues/3663))

  This was responsible for some E2E test flakiness.

- beacon: Add a minimal gRPC service
  ([#3666](https://github.com/oasisprotocol/oasis-core/issues/3666))

- go/worker/beacon: Fix a state recovery edge case
  ([#3668](https://github.com/oasisprotocol/oasis-core/issues/3668))

- go/consensus/tendermint/abci/mux: Reject early `EstimateGas` calls
  ([#3669](https://github.com/oasisprotocol/oasis-core/issues/3669))

  With the new beacon, `EstimateGas` will not work till either `InitChain` or
  `BeginBlock` have been called successfully at least once.

- go/consensus: Add support for method priority
  ([#3675](https://github.com/oasisprotocol/oasis-core/issues/3675))

- go/oasis-node/cmd/common/metrics: Fix label escaping
  ([#3678](https://github.com/oasisprotocol/oasis-core/issues/3678))

- Make sure tracing is only enabled in debug mode
  ([#3679](https://github.com/oasisprotocol/oasis-core/issues/3679))

- rust: Bump bech32 from 0.7.2 to 0.8.0
  ([#3699](https://github.com/oasisprotocol/oasis-core/issues/3699))

- go/oasis-test-runner: Add support for configuring `pprof`
  ([#3719](https://github.com/oasisprotocol/oasis-core/issues/3719))

  Adds support for configuring `pprof` on the test nodes.

- go/oasis-test-runner: Configurable supplementary sanity checker
  ([#3719](https://github.com/oasisprotocol/oasis-core/issues/3719))

  Previously, supplementary sanity checker was always automatically started on
  the `validator-0`.

- Make: Remove `build-go` target's `go` alias
  ([#3722](https://github.com/oasisprotocol/oasis-core/issues/3722))

- Make: Add `lint-go-mod-tidy` target
  ([#3722](https://github.com/oasisprotocol/oasis-core/issues/3722))

- go: Bump github.com/golang/snappy from 0.0.2 to 0.0.3
  ([#3735](https://github.com/oasisprotocol/oasis-core/issues/3735))

- rust: Bump aesm-client from 0.5.1 to 0.5.2
  ([#3742](https://github.com/oasisprotocol/oasis-core/issues/3742))

- runtime/common/quantity: Add `Mul/Div` implementations
  ([#3744](https://github.com/oasisprotocol/oasis-core/issues/3744))

- go/nodes/grpc: Tweak backoff timeouts
  ([#3757](https://github.com/oasisprotocol/oasis-core/issues/3757))

  Before, the default storage commit timeout was less than `grpcBackoffMaxDelay`
  which made the storage commit request retries ineffective whenever the max
  delay was reached (e.g. first few requests after a storage node was
  restarted).

- go/consensus: Validate mode in `SetContextParameters`
  ([#3773](https://github.com/oasisprotocol/oasis-core/issues/3773))

  This makes sure consensus parameters can only be updated in `InitChain` and
  `EndBlock`.

  Previously, we only did this check for the core consensus parameters
  but it makes sense to extend it to all of the parameters.

- go/staking/tests/debug: Move into go/staking/tests package
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

- go/staking/tests: Generalize account handling and add delegations
  ([#3774](https://github.com/oasisprotocol/oasis-core/issues/3774))

- go: Bump github.com/hashicorp/go-multierror from 1.1.0 to 1.1.1
  ([#3777](https://github.com/oasisprotocol/oasis-core/issues/3777))

- go: Bump github.com/prometheus/common to 0.19.0
  ([#3779](https://github.com/oasisprotocol/oasis-core/issues/3779))

## 20.12 (2020-11-03)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 2.0.0     |
| Runtime Host      | 1.0.0     |
| Runtime Committee | 1.0.0     |

### Removals and Breaking Changes

- go/common/crypto: Bump ed25519 version
  ([#3458](https://github.com/oasisprotocol/oasis-core/issues/3458),
   [#3470](https://github.com/oasisprotocol/oasis-core/issues/3470),
   [#3471](https://github.com/oasisprotocol/oasis-core/issues/3471))

### Configuration Changes

- go/runtime/scheduling: Max queue size flag rename
  ([#3434](https://github.com/oasisprotocol/oasis-core/issues/3434))

  - `worker.executor.schedule_max_queue_size` ->
  `worker.executor.schedule_max_tx_pool_size`

- go/runtime/client: Add max transaction age
  ([#3443](https://github.com/oasisprotocol/oasis-core/issues/3443))

  Added `runtime.client.max_transaction_age` flag to configure number of
  consensus blocks after which a submitted runtime transaction is considered
  expired. Expired transactions are dropped by the client.

### Features

- go/runtime/scheduler: Switch to an ordered queue tx pool implementation
  ([#3434](https://github.com/oasisprotocol/oasis-core/issues/3434))

### Bug Fixes

- go/runtime/client: Runtime client should retry processing any failed blocks
  ([#3412](https://github.com/oasisprotocol/oasis-core/issues/3412))

- go/storage/client: Retry `ErrNodeNotFound` errors on write requests
  ([#3424](https://github.com/oasisprotocol/oasis-core/issues/3424))

- go/worker/common: check if active epoch exists in HandlePeerMsg
  ([#3432](https://github.com/oasisprotocol/oasis-core/issues/3432))

  Fixes nil pointer dereference that can happen if the executor node tries to
  publish a message before it is synced

- go/runtime/client: Wait for initial consensus block and group version
  ([#3443](https://github.com/oasisprotocol/oasis-core/issues/3443))

  Before, the runtime client would publish invalid messages before obtaining the
  initial group version. The messages were correctly retired upon receiving the
  group version, but this resulted in needless messages.

- Storage node should update access control policy on new node registrations
  ([#3453](https://github.com/oasisprotocol/oasis-core/issues/3453))

  Before, the storage node only updated policy when existing nodes updated
  registrations or committee changed. This missed the case when new storage
  node registered mid-epoch.

- rust: Bump futures to 0.3.7
  ([#3460](https://github.com/oasisprotocol/oasis-core/issues/3460))

  Fixes [RUSTSEC-2020-0059].

  [RUSTSEC-2020-0059]: https://rustsec.org/advisories/RUSTSEC-2020-0059

## 20.11.3 (2020-10-16)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 1.0.0     |
| Runtime Host      | 1.0.0     |
| Runtime Committee | 1.0.0     |

### Bug Fixes

- go/storage/mkvs: Fix Finalize after checkpoint restore
  ([#3330](https://github.com/oasisprotocol/oasis-core/issues/3330))

### Internal Changes

- go/storage/mkvs: Add node tracking to chunk restore
  ([#3241](https://github.com/oasisprotocol/oasis-core/issues/3241))

- go: Add ability to set initial block height at genesis
  ([#3416](https://github.com/oasisprotocol/oasis-core/issues/3416))

## 20.11.2 (2020-10-13)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 1.0.0     |
| Runtime Host      | 1.0.0     |
| Runtime Committee | 1.0.0     |

### Features

- go/runtime/client: remove unneeded P2P message republishing
  ([#3325](https://github.com/oasisprotocol/oasis-core/issues/3325))

### Bug Fixes

- go/worker/p2p: Skip peer authentication for our own messages
  ([#3319](https://github.com/oasisprotocol/oasis-core/issues/3319))

  In practice this fixes a bug in a setup where executor nodes are used to
  submit runtime transactions. The executor nodes that are not part of the
  active committee, would end up self-rejecting transaction messages.

- go/worker/executor: don't unnecessarily hold the lock during storage requests
  ([#3320](https://github.com/oasisprotocol/oasis-core/issues/3320))

- go/worker/executor: only remove incoming transactions on finalized round
  ([#3332](https://github.com/oasisprotocol/oasis-core/issues/3332))

  Simplifies the executor to only remove transactions from the incoming queue
  once a round is successfully finalized. Before, the proposing executor also
  removed transactions when proposing a batch, which was an unneeded leftover
  from before the transaction scheduler committee was merged with into executor.

  Also fixes an edge case where batch was not reinserted on failed rounds.

- go/worker/common/committee: group version should be the epoch block
  ([#3347](https://github.com/oasisprotocol/oasis-core/issues/3347))

  When node is restarted, `EpochTransition` is called on the first received
  block, which is not necessary the actual epoch transition block. Therefore the
  epoch block needs to be queried to obtain the correct group version.

- go: Seed node support configuring tendermint P2P settings
  ([#3356](https://github.com/oasisprotocol/oasis-core/issues/3356))

  Seed node now supports configuring relevant tendermint P2P settings via
  existing tendermint configuration flags.

- go: Seed node panics on `oasis-node control` CLI
  ([#3356](https://github.com/oasisprotocol/oasis-core/issues/3356))

  Seed node now implements the missing consensus backend methods and supports
  `oasis-node control` CLI.

- go/worker/p2p: Correctly update peers on `WatchNodeList` events
  ([#3378](https://github.com/oasisprotocol/oasis-core/issues/3378))

- go/registry.WatchNodeList: return current node list upon subscription
  ([#3379](https://github.com/oasisprotocol/oasis-core/issues/3379))

- go/worker/p2p: Relay some permanent errors
  ([#3386](https://github.com/oasisprotocol/oasis-core/issues/3386))

  Before the P2P worker would not relay any messages failing with a permanent
  error. However there are cases where the client should permanently fail the
  dispatch, but still relay the message to peers.

  Adds `Relayable` error wrapper which can be used in handlers to notify that a
  message should be relayed regardless if the error is permanent or not.

- go/worker/p2p: Retry messages we consider permanent
  ([#3386](https://github.com/oasisprotocol/oasis-core/issues/3386))

  `p2pError.IsPermanent` notion of a permanent error differs from the upstream
  `cenkalti/backoff/v4` notion. Correctly retry on `context.Canceled` errors as
  we don't consider them permanent.

- go/consensus/tendermint: Backport bug fixes
  ([#3398](https://github.com/oasisprotocol/oasis-core/issues/3398))

### Internal Changes

- go/backoff: Update `cenkalti/backoff` to 4.1.0
  ([#3390](https://github.com/oasisprotocol/oasis-core/issues/3390))

- rust: bump crossbeam from 0.7.3 to 0.8.0
  ([#3394](https://github.com/oasisprotocol/oasis-core/issues/3394))

## 20.11.1 (2020-10-07)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 1.0.0     |
| Runtime Host      | 1.0.0     |
| Runtime Committee | 1.0.0     |

### Features

- go/consensus: add last retained block information
  ([#3348](https://github.com/oasisprotocol/oasis-core/issues/3348))

  New in the consensus API, the status struct now has information about
  the earliest block available on this node. This differs from the
  genesis block when pruning is enabled.

### Internal Changes

- go: Update to build on macOS
  ([#3333](https://github.com/oasisprotocol/oasis-core/issues/3333))

## 20.11 (2020-09-23)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 1.0.0     |
| Runtime Host      | 1.0.0     |
| Runtime Committee | 1.0.0     |

### Configuration Changes

- go/worker/p2p: Configurable libp2p buffer sizes
  ([#3264](https://github.com/oasisprotocol/oasis-core/issues/3264))

  Added `worker.p2p.peer_outbound_queue_size` and
  `worker.p2p.validate_queue_size` flags for configuring libp2p buffer sizes.

### Features

- Introduce the *canonical* form of a Genesis file
  ([#2757](https://github.com/oasisprotocol/oasis-core/issues/2757))

  This form is the pretty-printed JSON file with 2-space indents, where:

  - Struct fields are encoded in the order in which they are defined in the
    corresponding struct definitions.
  - Maps have their keys converted to strings which are then encoded in
    lexicographical order.

  For more details, see the [Genesis Document] documentation.

  The `oasis-node genesis init` and `oasis-node genesis dump` CLI commands are
  updated to output Genesis file in this canonical form.

  [Genesis Document]: docs/consensus/genesis.md

- go/staking/api: Add `PrettyPrintCommissionScheduleIndexInfixes()` helper
  ([#3265](https://github.com/oasisprotocol/oasis-core/issues/3265))

- go/staking/api: Update commission schedule rate and rate bound pretty prints
  ([#3265](https://github.com/oasisprotocol/oasis-core/issues/3265))

  Pretty print rates and rate bounds as enumerated lists to enable easier
  inspection of commission schedule (amendments) in combination with a
  hardware-based signer plugin.

- go/worker/executor: Cache last seen runtime transactions
  ([#3274](https://github.com/oasisprotocol/oasis-core/issues/3274))

  To enable a basic form of runtime transaction replay prevention, the
  transaction scheduler maintains a LRU cache of last seen runtime transactions
  keyed by transaction hash.

- go/worker/p2p: Use hash of the message payload as message ID
  ([#3275](https://github.com/oasisprotocol/oasis-core/issues/3275))

- go/oasis-node: Make `oasis-node genesis check` command check if form canonical
  ([#3298](https://github.com/oasisprotocol/oasis-core/issues/3298))

### Bug Fixes

- runtime/client: Skip not yet published requests in retry check
  ([#3264](https://github.com/oasisprotocol/oasis-core/issues/3264))

- go/consensus/tendermint: Don't swallow recheck result errors
  ([#3267](https://github.com/oasisprotocol/oasis-core/issues/3267))

- go/runtime/client: Fix possible panic on shutdown
  ([#3271](https://github.com/oasisprotocol/oasis-core/issues/3271))

- go/worker/registration: Verify entity exists before node registration
  ([#3286](https://github.com/oasisprotocol/oasis-core/issues/3286))

  This avoids some cases of failed node registration transactions when the
  entity under which the node is being registered does not actually exist.

- go/runtime/host/protocol: Set connection write deadline
  ([#3289](https://github.com/oasisprotocol/oasis-core/issues/3289))

  The RHP connection should have a write deadline to make sure that the
  connection is closed in case the runtime is not working.

- go/worker/executor: Clear tx queue before returning to committee
  ([#3300](https://github.com/oasisprotocol/oasis-core/issues/3300))

  Fixes a bug where an executor returning to committee would propose stale
  transactions that it received right before exiting committee in previous
  epoch, due to a race condition between adding transaction to the queue and
  clearing the queue.
  Clearing the incoming queue is now done before node starts being a compute
  worker instead of after it stops being.

- go/oasis-node: Start internal gRPC server before consensus backend
  ([#3303](https://github.com/oasisprotocol/oasis-core/issues/3303))

### Documentation Improvements

- Document [`oasis-node genesis` CLI commands]
  ([#3298](https://github.com/oasisprotocol/oasis-core/issues/3298))

  [`oasis-node genesis` CLI commands]: docs/oasis-node/cli.md#genesis

### Internal Changes

- ci/txsource: Shut down nodes for longer period of time
  ([#3223](https://github.com/oasisprotocol/oasis-core/issues/3223))

- rust: Update tiny-keccak, hmac, sha2 dependencies
  ([#3260](https://github.com/oasisprotocol/oasis-core/issues/3260))

- go/extra/stats: Remove the unmaintained `extra/stats` tool
  ([#3270](https://github.com/oasisprotocol/oasis-core/issues/3270))

- go/oasis-test-runner: Add `e2e/genesis-file` scenario
  ([#3278](https://github.com/oasisprotocol/oasis-core/issues/3278))

- go/ci: Update nancy to 1.0.0
  ([#3283](https://github.com/oasisprotocol/oasis-core/issues/3283))

- go/consensus/tests: Use explicit latest height when comparing query results
  ([#3287](https://github.com/oasisprotocol/oasis-core/issues/3287))

  Fixes flakiness in the test that occurred when a different height was used
  for the `GetTransactions` and `GetTransactionsWithResults` queries.

- go/e2e/sentry: Sanity check consensus peers
  ([#3291](https://github.com/oasisprotocol/oasis-core/issues/3291))

  Sentry E2E test now ensures that validators running behind sentries only
  connect to their sentry nodes.

- rust: Bump serde crates
  ([#3294](https://github.com/oasisprotocol/oasis-core/issues/3294))

  - `serde_cbor@0.10.2` -> `serde_cbor@0.11.1`

  - `serde@1.0.71` -> `serde@1.0.116`

  - `serde_bytes@0.10.5` -> `serde@0.11.5`

- rust: Bump snow version from 0.6.2 to 0.7.1
  ([#3296](https://github.com/oasisprotocol/oasis-core/issues/3296))

- go: Bump github.com/golang/snappy from 0.0.1 to 0.0.2
  ([#3297](https://github.com/oasisprotocol/oasis-core/issues/3297))

- rust: bump ed25519-dalek from 1.0.0 to 1.0.1
  ([#3299](https://github.com/oasisprotocol/oasis-core/issues/3299))

## 20.10 (2020-09-09)

| Protocol          | Version   |
|:------------------|:---------:|
| Consensus         | 1.0.0     |
| Runtime Host      | 1.0.0     |
| Runtime Committee | 1.0.0     |

### Removals and Breaking Changes

- go/staking: Remove WatchTransfers/Burns/Escrows in favor of WatchEvents
  ([#3080](https://github.com/oasisprotocol/oasis-core/issues/3080))

  The separate WatchTransfers/Burns/Escrows methods provided less information
  than the more general WatchEvents, namely they were missing the height and tx
  hash. There is no good reason to maintain both as the individual methods can
  be easily replaced with WatchEvents.

- go/roothash: Drop support for multiple committees
  ([#3179](https://github.com/oasisprotocol/oasis-core/issues/3179))

  Since there is currently no transaction scheduler implementation which would
  support multiple committees, there is no sense in having the merge node as it
  could be a source of bugs.

  The merge node is also the only client for the Merge* storage operations, so
  they can just be removed in order to reduce the exposed API surface.

- go/worker/executor: Support multiple transaction schedulers
  ([#3184](https://github.com/oasisprotocol/oasis-core/issues/3184))

  Transaction scheduling committee is removed and the transaction scheduler
  worker is merged into the executor worker. Transaction scheduling gRPC service
  is removed and runtime transaction submission is now done via libp2p's
  gossipsub.

  Each active executor worker now also acts as a transaction scheduler.
  Each round one of the executors acts as the scheduler and is expected to
  propose a batch for scheduling. Nodes switch between schedulers in round-robin
  fashion.

  Metric changes:

  Existing transaction scheduler incoming queue size metrics was renamed:

  - `oasis_worker_txnscheduler_incoming_queue_size` ->
  `oasis_worker_incoming_queue_size`

- go/runtime/scheduling: Rename "batching" algorithm to "simple"
  ([#3184](https://github.com/oasisprotocol/oasis-core/issues/3184))

  Note: Existing deployments will need to alter the state dump and fix the
  scheduling algorithm in all registered compute runtimes.

- go/consensus/tendermint: Bump Tendermint Core to v0.34-rc4-oasis2
  ([#3186](https://github.com/oasisprotocol/oasis-core/issues/3186),
   [#3229](https://github.com/oasisprotocol/oasis-core/issues/3229))

- go/roothash: Add support for executor triggered timeouts
  ([#3199](https://github.com/oasisprotocol/oasis-core/issues/3199))

  Executors can now trigger a roothash timeout in case there are new
  transactions waiting to be proposed, but the current transaction scheduler is
  not proposing a batch. The timeout can only happen once sufficient
  (configurable via a new `ProposerTimeout` runtime parameter) consensus blocks
  pass since the round started. The proposer timeout causes the current round to
  fail.

  Note: Existing deployments will need to alter the state dump to fix existing
  runtimes that do not have `ProposerTimeout` configured.

- go/common/cbor: Bump fxamacker/cbor to bafca87fa6db
  ([#3204](https://github.com/oasisprotocol/oasis-core/issues/3204))

  This should result in some smaller payloads as omitempty should work better
  for our use cases now.

- go/roothash: Change runtime round timeout to be in blocks
  ([#3210](https://github.com/oasisprotocol/oasis-core/issues/3210))

  Note: Existing deployments will need to alter the state dump and update the
  executor round timeout in all registered compute runtimes.

- go/common/crypto/signature: Remove `SignerRole.FromString()` method
  ([#3225](https://github.com/oasisprotocol/oasis-core/issues/3225))

  Use the newly added `SignerRole.UnmarshalText()` method instead.

- go/consensus: Simplify light client API
  ([#3229](https://github.com/oasisprotocol/oasis-core/issues/3229))

  Methods `GetSignedHeader` and `GetValidatorSet` have been replaced with
  `GetLightBlock` which provides both the signed header and the validator set.
  This makes sense as the two are commonly used together so this saves a
  round-trip.

- release: Wrap files in the release tarball in a single directory
  ([#3232](https://github.com/oasisprotocol/oasis-core/issues/3232))

- release: Use `SHA256SUMS-<VERSION>.txt` name template for checksum files
  ([#3232](https://github.com/oasisprotocol/oasis-core/issues/3232))

- Bump protocol versions to 1.0.0 in preparation for the Mainnet
  ([#3249](https://github.com/oasisprotocol/oasis-core/issues/3249))

  As described in our [Versioning scheme], we will bump the protocol versions
  (Consensus, Runtime Host, Runtime Committee) to version 1.0.0 when preparing
  an Oasis Core release for the Mainnet, which signifies they are ready for
  production use.

  [Versioning scheme]:
    docs/versioning.md#mainnet-and-version-100

### Configuration Changes

- Added `worker.p2p.enabled` flag to explicitly enable P2P worker
  ([#3184](https://github.com/oasisprotocol/oasis-core/issues/3184))

  Note: compute workers will automatically enable the P2P worker. The P2P worker
  needs to be manually enabled on runtime-client nodes that want to submit
  runtime transactions.

- go/worker/compute/executor: Remove transaction scheduler worker
  ([#3184](https://github.com/oasisprotocol/oasis-core/issues/3184))

  The `worker.txn_scheduler.check_tx.enabled` flag has been renamed to
  `worker.executor.schedule_check_tx.enabled`.
  The `worker.txnscheduler.batching.max_queue_size` flag has been renamed to
  `worker.executor.schedule_max_queue_size`.

- go/runtime/scheduling: Rename "batching" algorithm to "simple"
  ([#3184](https://github.com/oasisprotocol/oasis-core/issues/3184))

  The following `oasis-node registry runtime` command line flags have been
  renamed:

  - `runtime.txn_scheduler.batching.max_batch_size` to
  `runtime.txn_scheduler.max_batch_size`.
  - `runtime.txn_scheduler.batching.max_batch_size_bytes` to
  `runtime.txn_scheduler.max_batch_size_bytes`.

- go/common/crypto/signature: Use descriptive names for Signer roles
  ([#3225](https://github.com/oasisprotocol/oasis-core/issues/3225))

  The `--signer.composite.backends` CLI flag previously accepted integer-indexed
  Signer roles, e.g:

  ```
  --signer.composite.backends 1:file,2:file,3:file,4:plugin
  ```

  Now, it only accepts descriptive string names for Signer roles, e.g.:

  ```
  --signer.composite.backends entity:file,node:file,p2p:file,consensus:plugin
  ```

### Features

- go/consensus/api/transaction: Pretty-print transaction's fee amount in tokens
  ([#3151](https://github.com/oasisprotocol/oasis-core/issues/3151))

- go/consensus/api/transaction: Implement `PrettyPrinter` interface for `Fee`
  ([#3167](https://github.com/oasisprotocol/oasis-core/issues/3167))

- go/staking/api/token: Initial implementation
  ([#3167](https://github.com/oasisprotocol/oasis-core/issues/3167))

- go/consensus/tendermint: Support configurable initial height
  ([#3186](https://github.com/oasisprotocol/oasis-core/issues/3186))

- go/consensus: Add the `GetUnconfirmedTransactions` method
  ([#3187](https://github.com/oasisprotocol/oasis-core/issues/3187))

  The new method allows the caller to query the current set of transactions in
  the mempool (e.g., known transactions which have not yet been included in a
  block).

- go/consensus: Add `ErrDuplicateTx` error for duplicate transactions
  ([#3192](https://github.com/oasisprotocol/oasis-core/issues/3192))

- go/common/crypto/signature: Add new methods to `SignerRole` type
  ([#3225](https://github.com/oasisprotocol/oasis-core/issues/3225))

  Add `String()`, `MarshalText()` and `UnmarshalText()` methods to `SignerRole`
  type.

  Add `SignerEntityNode`, `SignerNodeName`, `SignerP2PName`,
  `SignerConsensusName` constants that represent the names of the corresponding
  Signer roles.

- release: Add `oasis-remote-signer` binary to the release tarball
  ([#3226](https://github.com/oasisprotocol/oasis-core/issues/3226))

- go: Unify CLI tools' version display and also display the Go toolchain version
  ([#3233](https://github.com/oasisprotocol/oasis-core/issues/3233))

- go/oasis-node/cmd/common: Add `SetBasicVersionTemplate()` function
  ([#3233](https://github.com/oasisprotocol/oasis-core/issues/3233))

  It can be used to set a basic custom version template for the given cobra
  command that shows the version of Oasis Core and the Go toolchain.

- go/control: Add per-runtime status report
  ([#3234](https://github.com/oasisprotocol/oasis-core/issues/3234))

  An additional `runtimes` field has been added to the output of the
  `control.GetStatus` method (e.g., as reported by `control status`
  subcommand). The field contains a map of supported runtime IDs to their
  runtime-specific status reports.

### Bug Fixes

- go/common/crypto/drbg: Also consider empty slices as Null values
  ([#3165](https://github.com/oasisprotocol/oasis-core/issues/3165))

  The wrong handling of an edge case in the HMAC_DRBG implementation has been
  corrected. An update with empty `additional_data` now behaves the same as an
  update with nil additional data. While the spec is not 100% clear around how
  this is to be treated, supplemental documentation suggests that this is the
  correct way to handle it.

  Oasis code never uses HMAC_DRNG with a non-nil empty `additional_data`
  parameter, so nothing changes for Oasis users.

- go/consensus/tendermint: Sync state database before discarding versions
  ([#3173](https://github.com/oasisprotocol/oasis-core/issues/3173))

  Otherwise a crash can cause the state database to be rolled back to a version
  that has already been discarded from Tendermint's state stores which would
  prevent replay on restart.

  Discovered during long-term tests.

- go/genesis: Remove time sanity check
  ([#3178](https://github.com/oasisprotocol/oasis-core/issues/3178))

  Previously the genesis document sanity check rejected genesis documents with
  future timestamps which made it awkward to prepare the node in advance. Since
  the only supported consensus backend (Tendermint) can handle future
  timestamps by delaying the consensus process, allow such genesis documents.

- go/registry/runtime: Validate runtime transaction scheduler parameters
  ([#3184](https://github.com/oasisprotocol/oasis-core/issues/3184))

  Note: Existing deployments might need to alter the runtime state dump in case
  existing registered runtimes have invalid parameters configured.

- runtime: Use separate cache for checking transactions
  ([#3191](https://github.com/oasisprotocol/oasis-core/issues/3191))

  This allows calling both check and execute methods against the same runtime
  instance.

- Executor should refresh runtime scheduling parameters
  ([#3203](https://github.com/oasisprotocol/oasis-core/issues/3203))

  Fixes the executor node to watch for runtime scheduling parameter changes and
  if needed update its scheduling configuration.

- go/roothash: Make the parent block check earlier
  ([#3206](https://github.com/oasisprotocol/oasis-core/issues/3206))

- go/registry: Correctly propagate lookup errors
  ([#3209](https://github.com/oasisprotocol/oasis-core/issues/3209))

- go/oasis-node: Omit existing entity check for non-file signers
  ([#3215](https://github.com/oasisprotocol/oasis-core/issues/3215))

  The "registry entity init" subcommand previously always performed a check
  whether an entity already exists. It did that by creating an additional
  signer factory to perform this check.

  Some signers assign exclusive access to an underlying resource (e.g., HSM) to
  the given factory. In that case, all operations on the second signer factory
  would fail. Thus we now omit the existing entity check for non-file signers.

- go: Fix CLI tools to not print error messages twice
  ([#3230](https://github.com/oasisprotocol/oasis-core/issues/3230))

- go/runtime/transaction: Ensure consistent batch order indices
  ([#3248](https://github.com/oasisprotocol/oasis-core/issues/3248))

- go/worker/storage: Always use fresh nodes for policy updates
  ([#3252](https://github.com/oasisprotocol/oasis-core/issues/3252))

- go/worker/common: Use group-synced storage client
  ([#3253](https://github.com/oasisprotocol/oasis-core/issues/3253))

  Previously the runtime worker(s) used the common storage client which was not
  synced with any particular committee version. This could cause an executor
  node to use a stale storage node for storing updates.

### Documentation Improvements

- Add documentation example on the process of registering and running a runtime
  ([#3081](https://github.com/oasisprotocol/oasis-core/issues/3081),
   [#3207](https://github.com/oasisprotocol/oasis-core/issues/3207),
   [#3228](https://github.com/oasisprotocol/oasis-core/issues/3228))

- Expand documentation on test vectors
  ([#3205](https://github.com/oasisprotocol/oasis-core/issues/3205))

- Fix staking account address derivation description to match what the code does
  ([#3240](https://github.com/oasisprotocol/oasis-core/issues/3240))

- ADR 0002: Go Modules Compatible Git Tags
  ([#3242](https://github.com/oasisprotocol/oasis-core/issues/3242))

  Go Modules only allow [Semantic Versioning 2.0.0] for
  [versioning of the modules][go-mod-ver] which makes it hard to work
  with [Oasis Core's CalVer (calendar versioning) scheme].

  Design a scheme for tagging Oasis Core releases with Go Modules compatible Git
  tags (in addition to the ordinary Git tags).

  [Semantic Versioning 2.0.0]:
    https://semver.org/spec/v2.0.0.html
  [go-mod-ver]:
    https://golang.org/ref/mod#versions
  [Oasis Core's CalVer (calendar versioning) scheme]:
    docs/versioning.md

### Internal Changes

- go/storage/mkvs: Add NoPersist commit option
  ([#2186](https://github.com/oasisprotocol/oasis-core/issues/2186))

  Using the NoPersist commit option makes the Commit only compute all the
  hashes but does not persist any roots in the database.

- go/oasis-test-runner: Add support for funding entities in genesis
  ([#3081](https://github.com/oasisprotocol/oasis-core/issues/3081))

  Additionally, make the default fixture command a bit more configurable.

- go/worker/storage: Add initial sync from checkpoints
  ([#3181](https://github.com/oasisprotocol/oasis-core/issues/3181))

  Instead of relying on the slow per-block root sync, the worker now tries
  syncing from checkpoints, if any suitable are found.

- Update Badger version to v2.2007.2
  ([#3182](https://github.com/oasisprotocol/oasis-core/issues/3182),
   [#3227](https://github.com/oasisprotocol/oasis-core/issues/3227))

- go/oasis-test-runner: Fix e2e/consensus-state-sync scenario
  ([#3194](https://github.com/oasisprotocol/oasis-core/issues/3194))

  Instead of terminating the validator-to-be-synced immediately and restarting
  it later, do not even start it. Early stopping could result in state that
  prevents proper state sync later.

- Bump Go to 1.15.1
  ([#3197](https://github.com/oasisprotocol/oasis-core/issues/3197))

- go: Explicitly use public key pinning for certificate verification
  ([#3197](https://github.com/oasisprotocol/oasis-core/issues/3197))

  While we only ever use public key pinning for authenticating TLS connections,
  some places still used the regular TLS config with a single certificate in
  the certificate pool. This causes failures on Go 1.15+ due to CommonName
  checks being deprecated, even if we never used hostnames for authentication.

  This changes all cases to use our explicit public key pinning credentials for
  gRPC connections.

- tests/txsource: Run queries workload against all nodes
  ([#3209](https://github.com/oasisprotocol/oasis-core/issues/3209))

- tests/txsource/queries: Verify consensus state integrity
  ([#3209](https://github.com/oasisprotocol/oasis-core/issues/3209))

- go/common/grpc: Add `IsErrorCode` helper method
  ([#3209](https://github.com/oasisprotocol/oasis-core/issues/3209))

- go/registry: Refactor runtime descriptor validity checks
  ([#3210](https://github.com/oasisprotocol/oasis-core/issues/3210))

- go/common/keyformat: Add support for int64
  ([#3210](https://github.com/oasisprotocol/oasis-core/issues/3210))

- go/roothash/tester: Fix flaky `RoundTimeoutWithEpochTransition`
  ([#3214](https://github.com/oasisprotocol/oasis-core/issues/3214))

- ci: run the daily test for 12 hours
  ([#3219](https://github.com/oasisprotocol/oasis-core/issues/3219))

- Bump Rust toolchain to nightly-2020-08-29 for LVI mitigation speedups
  ([#3231](https://github.com/oasisprotocol/oasis-core/issues/3231))

- go: Bump bleve to 1.0.10
  ([#3231](https://github.com/oasisprotocol/oasis-core/issues/3231))

- Update Go dependencies
  ([#3238](https://github.com/oasisprotocol/oasis-core/issues/3238),
   [#3255](https://github.com/oasisprotocol/oasis-core/issues/3255))

  - `cenkalti/backoff/v4`: v4.0.0 -> v4.0.2

  - `grpc-ecosystem/go-grpc-middleware`: f849b5445de4 -> v1.2.1

  - `hashicorp/go-multierror`: v1.0.0 -> v1.1.0

  - `libp2p/go-libp2p`: v0.10.2 -> v0.11.0

  - `libp2p/go-libp2p-pubsub`: v0.3.3 -> v0.3.5

  - `multiformats/go-multiaddr`: v0.2.2 -> v0.3.1

  - `prometheus/common`: v0.10.0 -> v0.13.0

  - `google.golang.org/grpc`: v1.31.0 -> v1.32.0

  - `google.golang.org/protobuf`: v1.23.0 -> v1.24.0

  Also updates the Go version in go.mod to 1.15.

- Configure [dependabot](https://dependabot.com/)
  ([#3239](https://github.com/oasisprotocol/oasis-core/issues/3239))

  Configures dependabot for Go, Rust and Github Actions.

- internal: Document how to include protocol versions in the Change Log
  ([#3249](https://github.com/oasisprotocol/oasis-core/issues/3249))

- go/runtime/committee: Support filtering nodes by tags
  ([#3253](https://github.com/oasisprotocol/oasis-core/issues/3253))

- Make: Augment `tag-next-release` to create a Go Modules compatible Git tag
  ([#3258](https://github.com/oasisprotocol/oasis-core/issues/3258))

  This implements the tagging scheme described in
  [ADR 0002: Go Modules Compatible Git Tags].

  <!-- markdownlint-disable line-length -->
  [ADR 0002: Go Modules Compatible Git Tags]:
    https://github.com/oasisprotocol/adrs/blob/main/0002-go-modules-compatible-git-tags.md
  <!-- markdownlint-enable line-length -->

## 20.9 (2020-08-05)

### Process

- Introduce [Architectural Decision Records]
  ([#2924](https://github.com/oasisprotocol/oasis-core/issues/2924))

  [Architectural Decision Records]:
    https://github.com/oasisprotocol/adrs/blob/main/README.md

- Remind to bump protocol versions before release
  ([#3097](https://github.com/oasisprotocol/oasis-core/issues/3097))

### Removals and Breaking Changes

- go/registry: Add MinWriteReplication to runtime storage parameters
  ([#1821](https://github.com/oasisprotocol/oasis-core/issues/1821))

  The MinWriteReplication specifies the minimum number of nodes to which any
  writes must be replicated before being assumed to be committed.

- go/common/cbor: Reject CBOR blobs with unknown fields
  ([#2020](https://github.com/oasisprotocol/oasis-core/issues/2020))

- go/consensus: Enable periodic state checkpoints
  ([#2880](https://github.com/oasisprotocol/oasis-core/issues/2880))

  This adds the following consensus parameters which control how state
  checkpointing is to be performed (currently not enforced):

  - `state_checkpoint_interval` is the interval (in blocks) on which state
    checkpoints should be taken.

  - `state_checkpoint_num_kept` is the number of past state checkpoints to
    keep.

  - `state_checkpoint_chunk_size` is the chunk size that should be used when
    creating state checkpoints.

- go/consensus/tendermint: Bump Tendermint Core to 0.34
  ([#2882](https://github.com/oasisprotocol/oasis-core/issues/2882))

- go/worker/common/p2p: Use libp2p's gossipsub
  ([#3010](https://github.com/oasisprotocol/oasis-core/issues/3010))

- go/registry: Add up node thresholds for each runtime
  ([#3027](https://github.com/oasisprotocol/oasis-core/issues/3027))

- go/registry: Make TLS address required for RoleConsensusRPC
  ([#3038](https://github.com/oasisprotocol/oasis-core/issues/3038))

- go/consensus/tendermint: Fix node update verification
  ([#3040](https://github.com/oasisprotocol/oasis-core/issues/3040))

- runtime: Cleanup some runtime host protocol messages
  ([#3055](https://github.com/oasisprotocol/oasis-core/issues/3055))

- go: Rename existing staking token to base unit
  ([#3061](https://github.com/oasisprotocol/oasis-core/issues/3061))

  This allows introducing the concept of staking token which is defined as a
  given number of base units.

  Additionally, rename fields of the following `go/staking/api` types:
  `TransferEvent`, `BurnEvent`, `AddEscrowEvent`, `TakeEscrowEvent`,
  `ReclaimEscrowEvent`, `Transfer`, `Burn`, `Escrow`, `ReclaimEscrow`.

- go/staking: Increase reward amount denominator
  ([#3065](https://github.com/oasisprotocol/oasis-core/issues/3065))

  This allows the genesis block writer to specify finer reward rates.

  Associated genesis controls analysis:

  ```
  RewardAmountDenominator
  |- AddRewards
  |  |- RewardFactorEpochElectionAny
  |  '- RewardFactorEpochSigned
  '- AddRewardSingleAttenuated
     '- RewardFactorBlockProposed
  ```

  Note to the genesis block writer: scale rewards factors **up** by a
  factor of **1,000**.

- go/registry/api: Remove `GetNodeList` method
  ([#3067](https://github.com/oasisprotocol/oasis-core/issues/3067))

  The `GetNodeList` method was unused and is therefore removed. Any code using
  this method can be migrated to use `GetNodes` instead.

- go/roothash/api: Include RuntimeID field in roothash events
  ([#3073](https://github.com/oasisprotocol/oasis-core/issues/3073))

- go/tendermint/roothash: Include RuntimeID attribute in events
  ([#3073](https://github.com/oasisprotocol/oasis-core/issues/3073))

  All tendermint roothash events now include "runtime-id" attribute.

- go/roothash/api: Add FinalizedEvent type to roothash events
  ([#3073](https://github.com/oasisprotocol/oasis-core/issues/3073))

- go/registry/api: Include transaction hash and height in all registry events
  ([#3073](https://github.com/oasisprotocol/oasis-core/issues/3073))

- go/backends: Return pointers in GetEvents methods
  ([#3092](https://github.com/oasisprotocol/oasis-core/issues/3092))

  To avoid unnecessary copying and to make the methods more unified with rest of
  the APIs, return pointers to events in backend GetEvents methods.

- go/consensus/tendermint: Use P2P key for Tendermint P2P
  ([#3101](https://github.com/oasisprotocol/oasis-core/issues/3101))

  Previously the Tendermint consensus backend used the node's identity key for
  Tendermint P2P connections. This has now been changed to use the node's P2P
  key instead as that can be made ephemeral in the future.

- go/oasis-test-runner/env: Rename types, fields, functions to refer to scenario
  ([#3108](https://github.com/oasisprotocol/oasis-core/issues/3108))

  Rename `TestInstanceInfo` type to `ScenarioInstanceInfo` and its `Test` field
  to `Scenario`.

  Rename `Env`'s `TestInfo()` and `WriteTestInfo()` methods to `ScenarioInfo()`
  and `WriteScenarioInfo()` for consistency.

- go/oasis-test-runner/cmd: Rename `--test` flag to `--scenario` flag
  ([#3108](https://github.com/oasisprotocol/oasis-core/issues/3108))

  Rename the short version from `-t` to `-s`.

- go/oasis-node/cmd/common/metrics: Rename "scenario" metrics label to "test"
  ([#3108](https://github.com/oasisprotocol/oasis-core/issues/3108))

- go/common/prettyprint: Augment `PrettyPrinter.PrettyPrint()` with `Context`
  ([#3111](https://github.com/oasisprotocol/oasis-core/issues/3111))

- go/oasis-node/cmd: Remove `--retry` flag from staking CLI commands
  ([#3113](https://github.com/oasisprotocol/oasis-core/issues/3113))

  Remove obsolete `--retry` flag from `oasis-node stake info`,
  `oasis-node stake list` and `oasis-node stake account info` CLI commands.

- go: Remove the integrated ledger support
  ([#3128](https://github.com/oasisprotocol/oasis-core/issues/3128))

  The signer and associated enumeration tool have been moved to
  oasisprotocol/oasis-core-ledger.

- go/oasis-node/cmd/common/consensus: Add `context.Context` to `SignAndSaveTx()`
  ([#3137](https://github.com/oasisprotocol/oasis-core/issues/3137))

- go/registry: Require SGX for non-test keymanager runtimes
  ([#3146](https://github.com/oasisprotocol/oasis-core/issues/3146))

  Note: Existing deployments might need to alter the state dump to fix any
  existing keymanager runtimes that registered without SGX hardware.

- go/registry: Require SGX for non-test compute runtimes using a key manager
  ([#3159](https://github.com/oasisprotocol/oasis-core/issues/3159))

  Note: Existing deployments might need to alter the state dump to fix any
  existing compute runtimes that registered without SGX hardware and have
  keymanager runtime configured.

### Configuration Changes

- Remove explicit evidence-related consensus parameters
  ([#2882](https://github.com/oasisprotocol/oasis-core/issues/2882))

  The following evidence-related consensus parameters have been removed as they
  are now derived based on the debonding period and other parameters:

  - `max_evidence_age_blocks`
  - `max_evidence_age_time`

  Make sure to update the genesis file.

- go/consensus/tendermint: Make configuration options consistent
  ([#3082](https://github.com/oasisprotocol/oasis-core/issues/3082))

  All Tendermint configuration option names have been changed to be
  consistently placed under `consensus.tendermint.`. This requires any previous
  options that started with `tendermint.` to be changed to start with
  `consensus.tendermint.`.

- Change the way seed-only nodes are configured
  ([#3116](https://github.com/oasisprotocol/oasis-core/issues/3116))

  The previous `--consensus.tendermint.p2p.seed_mode` configuration flag has
  been removed. In its place there is now a more general
  `--consensus.tendermint.mode` flag which should be set to `seed` in order to
  make the node a seed-only node.

### Features

- go/storage/client: Use MinWriteReplication when waiting for writes
  ([#1821](https://github.com/oasisprotocol/oasis-core/issues/1821))

- registry: Allow nodes to opt-in to more runtimes
  ([#2179](https://github.com/oasisprotocol/oasis-core/issues/2179))

  Previously, when a node updated its registration, the list of runtimes
  had to be identical.  It is now possible to add new runtimes.

- e2e/tests: Added runtime upgrade test
  ([#2520](https://github.com/oasisprotocol/oasis-core/issues/2520))

- go oasis-node: Add CLI command for estimating gas cost of a transaction
  ([#2723](https://github.com/oasisprotocol/oasis-core/issues/2723))

  This adds `oasis-node consensus estimate_gas`.

  This adds `--transaction.unsigned`.

- go/oasis-node/cmd: Show Genesis document's hash when displaying transactions
  ([#2871](https://github.com/oasisprotocol/oasis-core/issues/2871))

  Show Genesis document's hash when generating staking transactions with
  `oasis-node stake account gen_*` CLI commands and when showing transactions'
  pretty prints with the `oasis-node consensus show_tx` CLI command.

- go/consensus/tendermint: Add support for state sync
  ([#2880](https://github.com/oasisprotocol/oasis-core/issues/2880))

- go/registry/api: Add `GetNodeByConsensusAddress` method
  ([#2961](https://github.com/oasisprotocol/oasis-core/issues/2961))

  `GetNodeByConsensusAddress` can be used to query nodes by their Consensus
  address.

- go/identity/cli: Add show TLS pubkey commands
  ([#3015](https://github.com/oasisprotocol/oasis-core/issues/3015))

  Adds following CLI helpers for displaying TLS public keys:

  - `oasis-node identity show-tls-pubkey --datadir <datadir>` for displaying
  the public key used in the external node gRPC endpoints.
  - `oasis-node identity show-sentry-client-pubkey --datadir <datadir>` for
  displaying the public key used by the upstream nodes when connecting to the
  sentry control endpoint.

- go/oasis-node/cmd/stake: Support showing stake amounts in tokens
  ([#3037](https://github.com/oasisprotocol/oasis-core/issues/3037))

  The `oasis-node stake info` and `oasis-node stake account info` CLI commands
  show stake amounts (e.g. account balances, staking thresholds) in tokens.

- go/staking/api: Pretty-print account balances in tokens
  ([#3037](https://github.com/oasisprotocol/oasis-core/issues/3037))

  If a `PrettyPrinter`'s context carries appropriate values for the token's
  ticker symbol and token's value base-10 exponent, print the balance in
  tokens instead of base units.

- go/control: Add registration status to node status
  ([#3038](https://github.com/oasisprotocol/oasis-core/issues/3038))

  This updates the response returned by the `GetStatus` method exposed by the
  node controller service to include a `Registration` field that contains
  information about the node's current registration.

- go/control: Add identity status to node status
  ([#3038](https://github.com/oasisprotocol/oasis-core/issues/3038))

  This updates the response returned by the `GetStatus` method exposed by the
  node controller service to include an `Identity` field that contains
  information about the public keys used to identify a node in different
  contexts.

- go/consensus: Add IsValidator to reported node status
  ([#3038](https://github.com/oasisprotocol/oasis-core/issues/3038))

- go/consensus/api: Add `GetTransactionsWithResults` method
  ([#3047](https://github.com/oasisprotocol/oasis-core/issues/3047))

  `GetTransactionsWithResults` returns a list of transactions and their
  execution results, contained within a consensus block at a specific height.

- go/common/crypto/signature/signers/ledger: Descriptive error on user reject
  ([#3050](https://github.com/oasisprotocol/oasis-core/issues/3050))

  Make Ledger signer return a more descriptive error message when a user rejects
  a transaction on the Ledger device.

- go/common/crypto/signature/signers/ledger: Add support for consensus signer
  ([#3056](https://github.com/oasisprotocol/oasis-core/issues/3056))

  Add support for consensus signer that can be used with the Oasis Validator
  Ledger app.

- go/oasis-node/cmd/genesis: Allow setting staking token symbol and value exp
  ([#3061](https://github.com/oasisprotocol/oasis-core/issues/3061))

  Allow setting staking token's ticker symbol and token value's base-10 exponent
  in `oasis-node genesis init` CLI command via `--staking.token_symbol` and
  `--staking.token_value_exponent` flags.

- go/staking: Add `TokenSymbol` and `TokenValueExponent` fields to `Genesis`
  ([#3061](https://github.com/oasisprotocol/oasis-core/issues/3061))

  They allow denominating stake amounts in tokens (besides base units used
  internally).
  For more details, see [Staking Developer Docs].

  [Staking Developer Docs]:
    docs/consensus/services/staking.md#tokens-and-base-units

- go/control: List all valid TLS public keys in identity status
  ([#3062](https://github.com/oasisprotocol/oasis-core/issues/3062))

  This changes the `Identity` field in the reposnse of the `GetStatus` method
  exposed by the node controller service to include all valid TLS public keys
  for the node. This change affects nodes using automatic certificate rotation,
  which at any point use 2 valid TLS public keys.

- go/oasis-node: CLI support for the GetStatus endpoint
  ([#3064](https://github.com/oasisprotocol/oasis-core/issues/3064))

  See [docs/oasis-node/cli.md#status](/docs/oasis-node/cli.md#status).

- go/consensus: Expose read-only state via light client interface
  ([#3077](https://github.com/oasisprotocol/oasis-core/issues/3077))

  Nodes configured as consensus RPC services workers now expose read-only
  access to consensus state via the usual MKVS ReadSyncer interface, allowing
  light clients to remotely query state while transparently verifying proofs.

- go/oasis-node/cmd/stake: Show pretty-printed account info
  ([#3087](https://github.com/oasisprotocol/oasis-core/issues/3087))

  Change `oasis-node stake account info` CLI command to output pretty-printed
  account info instead of raw JSON data.

- go/staking/api: Implement `PrettyPrinter` interface for various types
  ([#3087](https://github.com/oasisprotocol/oasis-core/issues/3087),
   [#3132](https://github.com/oasisprotocol/oasis-core/issues/3132))

  Implement `PrettyPrinter` for `Transfer`, `Burn`, `Escrow`, `ReclaimEscrow`,
  `AmendCommissionSchedule`, `SharePool`, `StakeThreshold`, `StakeAccumulator`,
  `GeneralAccount`, `EscrowAccount`, `Account`, `CommissionRateStep`,
  `CommissionRateBoundStep` and `CommissionSchedule` types.

- go/worker/storage: Added round sync metrics
  ([#3088](https://github.com/oasisprotocol/oasis-core/issues/3088))

- go/registry: Add support for querying suspended runtimes
  ([#3093](https://github.com/oasisprotocol/oasis-core/issues/3093))

  Registry `GetRuntimes` method now accepts a parameter to enable querying for
  suspended runtimes.
  `WatchRuntimes` will now always include suspended runtimes in the initial
  response.

- go/consensus/tendermint: Support consensus backend modes
  ([#3116](https://github.com/oasisprotocol/oasis-core/issues/3116))

- go/common/crypto/signature: Add a plugin backed signer implementation
  ([#3120](https://github.com/oasisprotocol/oasis-core/issues/3120))

  Bloating the repository with a ton of different HSM (etc) signing
  backends doesn't make sense, and is a maintenance burden.  Use the
  go-plugin package to allow for externally distributed signer plugins.

- go/common/grpc: Client verbose logging and metrics
  ([#3121](https://github.com/oasisprotocol/oasis-core/issues/3121))

  Adds option to enable verbose logging for gRPC client and adds basic gRPC
  client instrumentation.

  Verbose gRPC client logging can be enabled with the existing `grpc.log.debug`
  flag.

  Metric changes:

  Existing gRPC server metrics were renamed:

  - `oasis_grpc_calls` -> `oasis_grpc_server_calls`
  - `oasis_grpc_latency` -> `oasis_grpc_server_latency`
  - `oasis_grpc_stream_writes` -> `oasis_grpc_server_stream_writes`

  Added corresponding metrics:

  - `oasis_grpc_client_calls` gRPC client calls metric.
  - `oasis_grpc_client_latency` gRPC client call latencies.
  - `oasis_grpc_client_stream_writes` gRPC client stream writes.

- go/common/prettyprint: Add `QuantityFrac()`
  ([#3129](https://github.com/oasisprotocol/oasis-core/issues/3129),
   [#3131](https://github.com/oasisprotocol/oasis-core/issues/3131))

- go/oasis-node/cmd/common/consensus: Ask for confirmation before signing
  ([#3134](https://github.com/oasisprotocol/oasis-core/issues/3134))

  If file signer is used, ask for confirmation before signing a transaction,
  unless `--assume_yes` flag is set.

- go/oasis-node/cmd/common/consensus: Pretty print transaction before signing it
  ([#3134](https://github.com/oasisprotocol/oasis-core/issues/3134))

  Adapt `oasis-node stake account gen_*` CLI commands to display stake amount in
  pretty printed transactions in token values.

- go/oasis-node/cmd/common/flags: Add `--assume_yes` flag
  ([#3137](https://github.com/oasisprotocol/oasis-core/issues/3137))

- go/oasis-node/cmd/common: Add `GetUserConfirmation()`
  ([#3137](https://github.com/oasisprotocol/oasis-core/issues/3137))

- go/oasis-node/cmd/common/consensus: Print helper text about transaction review
  ([#3149](https://github.com/oasisprotocol/oasis-core/issues/3149))

  If one uses the signer plugin and a TTY, print a helper text to notify him
  that he may need to review the transaction on the device if a hardware-based
  signer plugin is used.

- go/consensus: Add SubmitTxNoWait method
  ([#3152](https://github.com/oasisprotocol/oasis-core/issues/3152))

  The new method allows submitting a transaction without waiting for it to be
  included in a block.

- go/consensus/api/transaction: Add `PrettyPrintBody()` to `Transaction` type
  ([#3157](https://github.com/oasisprotocol/oasis-core/issues/3157))

- go/worker/keymanager: Ignore runtimes not in policy document
  ([#3162](https://github.com/oasisprotocol/oasis-core/issues/3162))

- go/consensus: Move SubmitEvidence to LightClientBackend
  ([#3169](https://github.com/oasisprotocol/oasis-core/issues/3169))

  This allows light clients to submit evidence of Byzantine behavior.

### Bug Fixes

- runtime: Reduce maximum RHP message size to 16 MiB
  ([#2213](https://github.com/oasisprotocol/oasis-core/issues/2213))

- go/worker/storage: Fix storage node policy
  ([#3021](https://github.com/oasisprotocol/oasis-core/issues/3021))

- runtime/dispatcher: Break recv loop on abort request
  ([#3023](https://github.com/oasisprotocol/oasis-core/issues/3023))

- go/runtime/host/sandbox: Fix possible data race
  ([#3024](https://github.com/oasisprotocol/oasis-core/issues/3024))

  The data race existed because the cancel function that is referenced inside a
  goroutine waiting for initialization to complete was unintentionally
  overwritten.

- go/consensus/tendermint: Properly handle no committed blocks
  ([#3032](https://github.com/oasisprotocol/oasis-core/issues/3032))

- runtime/committee/client: Reduce gRPC max backoff timeout
  ([#3035](https://github.com/oasisprotocol/oasis-core/issues/3035))

  Committee nodes are expected to be available and this timeout is more in line
  with timeouts used in the clients using these connections.

- go/worker/common/p2p: Don't treat context cancellation as permanent
  ([#3075](https://github.com/oasisprotocol/oasis-core/issues/3075))

  Context cancellation errors should not count as permanent for P2P dispatch as
  the cancelled context may be due to the round advancing in which case
  dispatch should actually be retried.

- go/oasis-test-runner/cmd: Sort scenarios for correct parallel execution
  ([#3104](https://github.com/oasisprotocol/oasis-core/issues/3104))

- oasis-node/cmd/unsafe-reset: Fix globs for runtime files
  ([#3105](https://github.com/oasisprotocol/oasis-core/issues/3105))

- go/oasis-node/cmd/common: ExportEntity should use the entity ctor
  ([#3117](https://github.com/oasisprotocol/oasis-core/issues/3117))

  Instead of using an entity populated with the zero values and a manually
  filled in public key, use the entity constructor that can fill in
  sensible values for things like the version.

- go/consensus/tendermint/roothash: Ignore non-tracked runtimes when reindexing
  ([#3124](https://github.com/oasisprotocol/oasis-core/issues/3124))

- go/tendermint/roothash: Skip pruned heights when reindexing
  ([#3127](https://github.com/oasisprotocol/oasis-core/issues/3127))

- go/worker/common: Treat stale unauthorized peer error as permanent
  ([#3133](https://github.com/oasisprotocol/oasis-core/issues/3133))

  If the message's group version indicates that the message is stale and an
  authorization check fails, treat the error as permanent as a stale message
  will never become valid.

- go/worker/compute: Enforce maximum batch sizes from txn scheduler
  ([#3139](https://github.com/oasisprotocol/oasis-core/issues/3139))

- Bump libp2p to 0.10.2
  ([#3150](https://github.com/oasisprotocol/oasis-core/issues/3150))

- go/storage/mkvs/checkpoint: Remove empty version directories
  ([#3160](https://github.com/oasisprotocol/oasis-core/issues/3160))

  When all root checkpoints are removed for a specific version, the version dir
  itself should also be removed.

- go/registry/metrics: Fix `oasis_registry_runtimes` metric
  ([#3161](https://github.com/oasisprotocol/oasis-core/issues/3161))

  Metric was counting runtime events, which does not correctly take into account
  the case where runtime is suspended and resumed.
  The metric is now computed by querying the registry.

### Documentation Improvements

- ADR 0000: Architectural Decision Records
  ([#2924](https://github.com/oasisprotocol/oasis-core/issues/2924))

  Introduce architectural decision records (ADRs) for keeping track of
  architecture decisions in a transparent way.

- docs/runtime: Update the Runtime Host Protocol section
  ([#2978](https://github.com/oasisprotocol/oasis-core/issues/2978))

- docs: Add the [Accounts section] of the Staking docs
  ([#3005](https://github.com/oasisprotocol/oasis-core/issues/3005))

  [Accounts section]: docs/consensus/services/staking.md#accounts

- go/staking/api: Document commission-related public types
  ([#3042](https://github.com/oasisprotocol/oasis-core/issues/3042))

- Add [Governance Model](GOVERNANCE.md)
  ([#3130](https://github.com/oasisprotocol/oasis-core/issues/3130))

- ADR 0001: Multiple Roots Under the Tendermint Application Hash
  ([#3136](https://github.com/oasisprotocol/oasis-core/issues/3136))

  Currently the Tendermint ABCI application hash is equal to the consensus
  state root for a specific height. In order to allow additional uses, like
  proving to light clients that specific events have been emitted in a block,
  we should make the application hash be derivable from potentially different
  kinds of roots.

- docs: Add cryptography section
  ([#3147](https://github.com/oasisprotocol/oasis-core/issues/3147))

### Internal Changes

- worker/sentry: Replace policy watcher with UpdatePolicies API method
  ([#2820](https://github.com/oasisprotocol/oasis-core/issues/2820))

  Previously, the sentry gRPC worker watched for policy changes, but
  now all policy changes are pushed to the sentry node via a new
  sentry API method, `UpdatePolicies`.

- go/oasis-test-runner: Use common cli package for provisioning runtimes
  ([#3021](https://github.com/oasisprotocol/oasis-core/issues/3021))

- go/common/encoding/bech32: Replace to-be-removed dependency
  ([#3030](https://github.com/oasisprotocol/oasis-core/issues/3030))

- ci: Don't automatically retry timed out jobs
  ([#3036](https://github.com/oasisprotocol/oasis-core/issues/3036))

- go/oasis-test-runner: Refactor E2E scenarios
  ([#3043](https://github.com/oasisprotocol/oasis-core/issues/3043))

  Previously there were some scenarios which incorrectly used the e2e/runtime
  base even though they do not need any runtimes to work. These have now been
  changed to use the e2e base instead.

- go/oasis-test-runner/cmd/common: Give verbose error when scenario is not found
  ([#3044](https://github.com/oasisprotocol/oasis-core/issues/3044))

  List all available scenarios if `oasis-test-runner` command is invoked with an
  unknown scenario.

- go/worker/compute/executor: Defer fetching the batch from storage
  ([#3049](https://github.com/oasisprotocol/oasis-core/issues/3049))

  There is no need to attempt to fetch the batch immediately, we can defer it to
  when we actually need to start processing the batch. This makes fetching not
  block P2P dispatch.

- go/worker/compute/merge: Defer finalization attempt
  ([#3049](https://github.com/oasisprotocol/oasis-core/issues/3049))

  There is no need for the finalization attempt to block handling of an incoming
  commitment as any errors from that are not propagated. This avoids blocking
  P2P relaying as well.

- go/oasis-test-runner: Support regexps for matching scenario names
  ([#3051](https://github.com/oasisprotocol/oasis-core/issues/3051))

- go/common/cbor: Add support for generic versioned blobs
  ([#3052](https://github.com/oasisprotocol/oasis-core/issues/3052))

- go/registry: Add transaction test vector generator
  ([#3059](https://github.com/oasisprotocol/oasis-core/issues/3059))

- go/common/prettyprint: Add PrettyType for use in test vectors
  ([#3059](https://github.com/oasisprotocol/oasis-core/issues/3059))

- go/consensus/tendermint/epochtime_mock: Fix initial notify
  ([#3060](https://github.com/oasisprotocol/oasis-core/issues/3060))

- go/tests/sentry: Add access control sanity checks
  ([#3062](https://github.com/oasisprotocol/oasis-core/issues/3062))

- ci/longtests: Setup prometheus monitoring
  ([#3090](https://github.com/oasisprotocol/oasis-core/issues/3090))

- go/consensus/tendermint: Refactor internal event handling
  ([#3091](https://github.com/oasisprotocol/oasis-core/issues/3091))

  Previously each consensus service client implemented its own event processing
  loop. All service clients now have a unified event loop implementation (each
  still runs in its own goroutine) that takes care of query subscriptions and
  event dispatch.

- go: Use gofumpt instead of gofmt to format Go
  ([#3095](https://github.com/oasisprotocol/oasis-core/issues/3095))

- go/oasis-test-runner/cmd: Limit scenario name regex matching
  ([#3103](https://github.com/oasisprotocol/oasis-core/issues/3103))

  Prevent oasis-test-runner to match too many scenarios for a given
  scenario name regex by ensuring the given scenario name regex matches
  the whole scenario name.

- go/tests/e2e: Add missing Clone() override to late-start
  ([#3106](https://github.com/oasisprotocol/oasis-core/issues/3106))

- go/oasis-test-runner: Refactor code to refer to scenario(s) consistently
  ([#3108](https://github.com/oasisprotocol/oasis-core/issues/3108))

- go/oasis-test-runner/oasis: Purge most of tests/fixture-data
  ([#3110](https://github.com/oasisprotocol/oasis-core/issues/3110))

- go/consensus/tendermint: Make New return consensus.Backend
  ([#3115](https://github.com/oasisprotocol/oasis-core/issues/3115))

- go/consensus/tendermint: Move GenesisProvider to api package
  ([#3115](https://github.com/oasisprotocol/oasis-core/issues/3115))

- go/consensus/tendermint: Move service.TendermintService to api.Backend
  ([#3115](https://github.com/oasisprotocol/oasis-core/issues/3115))

- go: Use `cbor.Versioned` for descriptor versioning
  ([#3119](https://github.com/oasisprotocol/oasis-core/issues/3119))

- go/e2e/txsource: Periodically restart runtime nodes
  ([#3124](https://github.com/oasisprotocol/oasis-core/issues/3124))

- ci: Extract go artifacts upload code into a script
  ([#3125](https://github.com/oasisprotocol/oasis-core/issues/3125))

- go/tests/e2e/history_reindex: Scenario that triggers roothash reindexing
  ([#3127](https://github.com/oasisprotocol/oasis-core/issues/3127))

- go/badger: bump badger version
  ([#3142](https://github.com/oasisprotocol/oasis-core/issues/3142))

- go/oasis-node: Fix the interactive prompt to be correct
  ([#3143](https://github.com/oasisprotocol/oasis-core/issues/3143))

## 20.8 (2020-06-16)

### Process

- release: Create a stable branch when preparing a new release
  ([#2993](https://github.com/oasisprotocol/oasis-core/issues/2993))

  Currently we create a stable release branch only once we need to backport some
  changes. This PR changes the release process to create the stable branch when
  creating a new release. This will ensure CI jobs hooked to stable/ branches,
  such as building a release tagged CI docker image, will be run for every
  release.

### Removals and Breaking Changes

- Change staking account ids/addresses to truncated hash of the public key
  ([#2928](https://github.com/oasisprotocol/oasis-core/issues/2928))

  Previously, staking account identifiers were called ids and were represented
  by a corresponding entity's public key.

  Now, they are called addresses and are represented by a truncated hash of a
  corresponding entity's public key, prefixed by a 1 byte address version.

  Furthermore, the new staking account addresses use the newly added Bech32
  encoding for text serialization with `oasis` as their human readable part
  (HRP) prefix.

- go/common/crypto/signature: Rename `NewBlacklistedKey()` function
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  Rename it to `NewBlacklistedPublicKey()` for consistency with the newly added
  `NewPublicKey()` function.

- go/staking/api: Rename `Accounts()` and `AccountInfo()` functions
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  Rename `Accounts()` function to `Addresses()` and `AccountInfo()` function to
  `Account()` to avoid ambiguity and better reflect their return value.

- go/consensus/api: Rename `Caller` field in `EstimateGasRequest` type
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  Rename `EstimateGasRequest`'s `Caller` field to `Signer` to better describe
  the field's value which is the public key of the transaction's signer.

- go/consensus/api: Use `staking.Address` in `GetSignerNonceRequest` type
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  Replace `GetSignerNonceRequest`'s `ID` field with `AccountAddress` field to
  reflect the recent staking account id/address change.

- Disallow v0 entity/node/runtime descriptors
  ([#2992](https://github.com/oasisprotocol/oasis-core/issues/2992))

- registry: Add runtime-specific staking thresholds
  ([#2995](https://github.com/oasisprotocol/oasis-core/issues/2995))

- go/staking: Rename fields in `Event` structure
  ([#3013](https://github.com/oasisprotocol/oasis-core/issues/3013))

  Fields in the `Event` structure are renamed to drop the `Event` suffix,
  breaking Go API compatibility. This has the following effect:

  - `TransferEvent` field is renamed to `Transfer`.

  - `BurnEvent` field is renamed to `Burn`.

  - `EscrowEvent` field is renamed to `Escrow`.

  The wire format of the event structure is unchanged.

- go/oasis-node/cmd/stake: Make `list` command's verbose output consistent
  ([#3016](https://github.com/oasisprotocol/oasis-core/issues/3016))

  Change `oasis-node stake list --verbose` CLI command's output to not list
  all accounts' information as a single-line JSON string but rather output
  each account's JSON string on a separate line.

### Configuration Changes

- Change staking account ids/addresses to truncated hash of the public key
  ([#2928](https://github.com/oasisprotocol/oasis-core/issues/2928))

  Due to this breaking change described above, the following configuration
  changes are needed:

  - In `oasis-node staking account info` CLI, the `--stake.account.id`
    option has been renamed to `--stake.account.address` and now accepts a
    Bech32 encoded account address.
  - In `oasis-node staking account gen_transfer` CLI, the
    `--stake.transfer.destination` option now accepts a Bech32 encoded account
    address.
  - In `oasis-node staking account gen_escrow` and
    `oasis-node staking account gen_reclaim_escrow` CLI, the
    `--stake.escrow.account` option now accepts a Bech32 encoded account
    address.

- go/worker/sentry: Do client authentication on sentry control grpc
  ([#3018](https://github.com/oasisprotocol/oasis-core/issues/3018))

  The following configuration changes are needed due to this change:

  - Added: `worker.sentry.control.authorized_pubkey` option to configure
  allowed upstream nodes. This should be set to sentry client TLS keys of
  upstream nodes.
  - Renamed: `worker.sentry.control_port` option to
  `worker.sentry.control.port`.

### Features

- go/worker/common: Allow specifying the path to the bwrap binary
  ([#1599](https://github.com/oasisprotocol/oasis-core/issues/1599))

  This adds a new config option `--worker.runtime.sandbox_binary` that
  allows overriding the path to the sandbox support binary (ie: bwrap).

- worker/compute/executor: Independently submit commit in case of faults
  ([#1807](https://github.com/oasisprotocol/oasis-core/issues/1807))

- go/common/encoding: Add `bech32` package implementing Bech32 encoding
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

- go/consensus/tendermint/apps/staking: Forbid txs for reserved addresses
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  Prevent reserved staking addresses (e.g. the common pool address) from being
  used as the from address in staking transactions.

- go/common/crypto: Add `address` package implementing a generic crypto address
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  It supports versioning and context separation and can be used to implement
  specific addresses, e.g. the staking account address.

- go/staking: Forbid reserved addresses in the Genesis
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  Prevent reserved staking addresses (e.g. the common pool address) from being
  used as an account in the Genesis' staking ledger or as an address in the
  Genesis' (debonding) delegations.

- go/common/crypto/signature: Add `NewPublicKey()` function
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  It creates a new public key from the given hex representation or panics.

- go/consensus/tendermint/api: Add `OwnTxSignerAddress()` to `ApplicationState`
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  It returns the transaction signer's staking address of the local node.

- go/staking/api: Add `Address` type for representing staking account addresses
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

- go/common/crypto/hash: Add `Truncate()` method to `Hash`
  ([#2940](https://github.com/oasisprotocol/oasis-core/issues/2940))

  It returns the first `n` bytes of a hash.

- runtime: Handle runtime interruptions gracefully
  ([#2991](https://github.com/oasisprotocol/oasis-core/issues/2991))

- go/oasis-node/cmd/stake: Add `pubkey2address` commmand
  ([#3003](https://github.com/oasisprotocol/oasis-core/issues/3003))

  Add `oasis-node stake pubkey2address` CLI command for converting a public key
  (e.g. an entity's ID) to a staking account address.

- go/roothash: Add commitment events
  ([#3013](https://github.com/oasisprotocol/oasis-core/issues/3013))

  The following two kinds of events are added to the roothash service:

  - `ExecutorCommittedEvent` emitted when the roothash service processes a
    commitment from an executor node.

  - `MergeCommittedEvent` emitted when the roothash service processes a
    commitment from a merge node.

### Bug Fixes

- staking: Don't emit zero-amount staking events
  ([#2983](https://github.com/oasisprotocol/oasis-core/issues/2983))

  If fees were set to 0, staking events related to the fee accumulator
  would still get emitted with zero amounts, which is pointless.

  This fix affects only events related to the internal fee accumulator
  and common pool accounts, manual transfers with 0 as the amount will
  still get emitted.

- Bump Rust toolchain to 2020-06-09 for LVI mitigations
  ([#2987](https://github.com/oasisprotocol/oasis-core/issues/2987))

- worker/compute: Retry local dispatch between workers
  ([#3000](https://github.com/oasisprotocol/oasis-core/issues/3000))

  If a node has multiple roles simultaneously, the local submissions
  don't go through P2P, but via a direct function call.
  This function call is now retried in case of errors.

- go/txsource: fix queries workload earliest committee epoch
  ([#3001](https://github.com/oasisprotocol/oasis-core/issues/3001))

- go/oasis-node: Support non-file signers in registry node init
  ([#3011](https://github.com/oasisprotocol/oasis-core/issues/3011))

### Documentation Improvements

- docs: Refactor setup instructions, add single validator node setup
  ([#3006](https://github.com/oasisprotocol/oasis-core/issues/3006))

### Internal Changes

- client: Rename the rpc crate to enclave_rpc
  ([#2469](https://github.com/oasisprotocol/oasis-core/issues/2469))

- runtime: Rename the rpc crate to enclave_rpc
  ([#2469](https://github.com/oasisprotocol/oasis-core/issues/2469))

- rust: Remove the use of the `failure` crate
  ([#2755](https://github.com/oasisprotocol/oasis-core/issues/2755))

  Using this crate is no longer considered best practice, and bugs in it
  have broken the build before.

  Note: Unfortunately the `runtime-loader` crate still uses this `failure`
  nonsense since the external Intel AESM client crate uses it for error
  handling.  Since it is a stand-alone binary it has been left as is.

- Makefile: update docker-shell target
  ([#2985](https://github.com/oasisprotocol/oasis-core/issues/2985))

- test/e2e/sentry: don't set seed node for nodes running with sentries
  ([#2989](https://github.com/oasisprotocol/oasis-core/issues/2989))

- ci: Remove push path filters for dockerfile build action
  ([#2997](https://github.com/oasisprotocol/oasis-core/issues/2997))

- go/consensus/tendermint: Refactor roothash event handling
  ([#3013](https://github.com/oasisprotocol/oasis-core/issues/3013))

  This makes roothash event handling similar to staking event handling, with
  common code paths for pubsub and polling-based calls.

  It also adds `Height` and `TxHash` to roothash events.

- ci: Make Buildkite fail if desired tag of Docker CI image doesn't exist
  ([#3016](https://github.com/oasisprotocol/oasis-core/issues/3016))

## 20.7 (2020-06-08)

### Removals and Breaking Changes

- go/registry: Avoid storing full TLS certificates
  ([#2556](https://github.com/oasisprotocol/oasis-core/issues/2556))

  Previously the node registry descriptor contained full TLS certificates for
  talking with nodes via gRPC. This changes it so that only TLS public keys are
  used when verifying peer certificates for TLS authentication.

  This makes the registry descriptors smaller and also makes it easier to pass
  around TLS identities (as public keys are much shorter).

  Obviously, this change BREAKS the consensus protocol and all previously
  signed node descriptors.

  The following configuration changes are needed due to this change:

  - In `oasis-node registry node` CLI, the `--node.committee_address` option
    has been renamed to `--node.tls_address` and the format has changed from
    `<certificate>@ip:port` to `<pubkey>@ip:port`.

  - For configuring sentry nodes on the workers, the
    `--worker.sentry.cert_file` has been _removed_. Instead, the
    `--worker.sentry.address` now takes the same address format as specified
    above (`<pubkey>@ip:port`).

  Previously signed node descriptors (v0) are considered valid at genesis time
  iff the node is exclusively a validator node as indicated by the role bits.
  Other nodes will need to be removed from genesis.

- Make `oasis_` Prometheus metrics help consistent
  ([#2602](https://github.com/oasisprotocol/oasis-core/issues/2602))

  Help messages for metrics starting with `oasis_` were revisited and made
  consistent. If you are using Prometheus and/or Push Gateway, you will need to
  clear Prometheus `data/` directory and restart the services to avoid
  inconsistency warnings.

- Refactor the runtime host APIs
  ([#2801](https://github.com/oasisprotocol/oasis-core/issues/2801))

  Several changes were made to the runtime host APIs used to provision and
  communicate with runtimes:

  - The runtime host implementation has been moved to `go/runtime/host`.

  - Some of the runtime host protocol types have been changed, all references
    to `Worker` in messages were renamed to `Runtime` to make it more clear
    what they refer to. Additionally, the `Error` message type has been changed
    to include additional fields (module and code) to make it easier to remap
    errors automatically.

    This makes it a BREAKING change for any existing runtimes.

  - Provisioning of a runtime is now performed by a `Provisioner` which is an
    interface. Implementations exist for (sandboxed) ELF binaries and Intel SGX
    enclaves. The implementations have been refactored to be more composable,
    so for example the SGX implementation only implements the SGX-related bits
    but uses the regular provisioner otherwise.

  - Configuration options for hosted runtimes have changed so existing configs
    will need to be _updated_ as follows:

    - The `--worker.runtime.backend` option has been renamed to
      `--worker.runtime.provisioner`.

    - The `--worker.runtime.loader` option has been renamed to
      `--worker.runtime.sgx.loader` and is now only required for supporting
      SGX runtimes. Non-SGX runtimes no longer need a loader.

    - The `--worker.runtime.binary` option has been renamed to
      `--worker.runtime.paths` and the value format has changed to be either
      a YAML map or a set of comma-separated key-value pairs separated by
      `=` (e.g., `<runtime-ID>=/path/to/binary`).

  - The key manager worker has been slightly changed to use the common runtime
    provisioning code. The following configuration options have been _removed_:

    - `--worker.keymanager.tee_hardware` as the TEE hardware is inferred
      from the runtime descriptor.

    - `--worker.keymanager.runtime.loader` and
      `--worker.keymanager.runtime.binary` as the common options mentioned
      above should be used instead.

- go/consensus/tendermint: Clean up indices in SetNode
  ([#2910](https://github.com/oasisprotocol/oasis-core/issues/2910))

- go/registry: Drop support for v0 node descriptor
  ([#2918](https://github.com/oasisprotocol/oasis-core/issues/2918))

### Configuration Changes

- go/oasis-node: Fix signer configuration via YAML
  ([#2949](https://github.com/oasisprotocol/oasis-core/issues/2949))

  The `--signer` argument has been renamed to `--signer.backend` to allow
  signer configuration to be passed via a YAML config. Previously, this would
  be impossible as `signer` would need to be both a string and a map at the
  same time when set via a YAML config.

### Features

- go/runtime/host/sgx: Add support for SIGSTRUCTs
  ([#1707](https://github.com/oasisprotocol/oasis-core/issues/1707))

  For now this will just generate one, signed with the same key that
  `runtime-loader` used to use (the Fortanix dummy key), but this will
  also support using file backed signatures, once we have an idea on how
  we are going to handle the process for such things.

- Add metrics for inter-node communcation
  ([#1771](https://github.com/oasisprotocol/oasis-core/issues/1771))

  - New `module` label was added to `oasis_codec_size` metric which contains
    information of the caller. Currently `p2p` value denotes a peer-to-peer
    message among Oasis nodes and `runtime-host` a message from/to enclave.
  - New `oasis_rhp_latency` summary metric for measuring Runtime Host
    communication latency was added.
  - New `oasis_rhp_successes` and `oasis_rhp_failures` counter metrics for
    counting number of successful and failed Runtime Host calls respectively
    were added.

- go/oasis-node/cmd/debug: Add the `dumpdb` command
  ([#2359](https://github.com/oasisprotocol/oasis-core/issues/2359))

  This command will attempt to extract the ABCI state from a combination
  of a shutdown node's on-disk database and the genesis document currently
  being used by the network, and will write the output as a JSON formatted
  genesis document.

  Some caveats:

  - It is not guaranteed that the dumped output will be usable as an
    actual genesis document without manual intervention.

  - Only the state that would be exported via a normal dump from a running
    node will be present in the dump.

  - The epochtime base will be that of the original genesis document, and
    not the most recent epoch (different from a genesis dump).

- e2e/tests: added keymanager runtime upgrade test
  ([#2517](https://github.com/oasisprotocol/oasis-core/issues/2517))

- Version signed entity, node and runtime descriptors
  ([#2581](https://github.com/oasisprotocol/oasis-core/issues/2581))

  This introduces a DescriptorVersion field to all entity, node and runtime
  descriptors to support future updates and handling of legacy descriptors at
  genesis.

  All new registrations only accept the latest version while initializing from
  genesis is also allowed with an older version to support a dump/restore
  upgrade.

- Add new consensus-related Prometheus metrics
  ([#2842](https://github.com/oasisprotocol/oasis-core/issues/2842))

  Four new metrics have been added:

  - `oasis_worker_epoch_number` is the current epoch number as seen by the
    worker.
  - `oasis_worker_node_registered` is a binary metric which denotes, if the
    node is registered.
  - `oasis_consensus_proposed_blocks` is the number of proposed Tendermint
    blocks by the node.
  - `oasis_consensus_signed_blocks` is the number of Tendermint blocks the node
    voted for.

- keymanager: Rename APIs referencing "contracts"
  ([#2844](https://github.com/oasisprotocol/oasis-core/issues/2844))

  Each runtime does not neccecarily have a notion for contracts, so the
  key manager now operates in terms of `KeyPairId`s that identify a given
  `KeyPair`.

- oasis-net-runner: add support for running networks with non-mock IAS
  ([#2883](https://github.com/oasisprotocol/oasis-core/issues/2883))

- go/stats: New availability v3 formula
  ([#2896](https://github.com/oasisprotocol/oasis-core/issues/2896))

  Here's the implementation of the new availability score v3 for May.

- consensus: Add GetStatus method to API
  ([#2902](https://github.com/oasisprotocol/oasis-core/issues/2902))

  A new `GetStatus` method has been added to the consensus API.
  It returns useful information about the latest block, the genesis
  block, and the node itself.

- control: Add GetStatus method to API
  ([#2902](https://github.com/oasisprotocol/oasis-core/issues/2902))

  A new `GetStatus` method has been added to the control API.
  It returns the software version and the status of the consensus layer.

- go/extra/stats: Give ties the same rank
  ([#2908](https://github.com/oasisprotocol/oasis-core/issues/2908))

  Previously records tied by availability score would get different
  ranks, which was wrong.

- go/oasis-node/cmd/common/metrics: Deprecate formal pushgateway support
  ([#2936](https://github.com/oasisprotocol/oasis-core/issues/2936))

  The prometheus authors do not recommend using it for most situations,
  it appears to be somewhat fragile, and we shouldn't be using it
  internally, so the functionality is now only usable if the correct
  debug-only flags are set.

- runtime/storage/mkvs: Add method for checking local key existence
  ([#2938](https://github.com/oasisprotocol/oasis-core/issues/2938))

  Adds a method to probe the local cache for key existence, guaranteeing
  that no remote syncing will be done.

- staking: Add WatchEvents
  ([#2944](https://github.com/oasisprotocol/oasis-core/issues/2944))

  A new method was added to the staking API, `WatchEvents`.  It returns
  a channel that produces a stream of staking `Event`s.
  The `Event` structure was also extended to include the block height.

- go/consensus/genesis: Add a public key blacklist
  ([#2948](https://github.com/oasisprotocol/oasis-core/issues/2948))

  This change adds a public key blacklist to the consensus parameters.
  All signatures made by public keys in the blacklist will be rejected.

  WARNING: For now the node will panic on startup if the genesis staking
  ledger has entries for blacklisted public keys.  By the time this
  feature is actually put to use (hopefully never), the staking ledger
  address format will be changed, resolving this caveat.

### Bug Fixes

- go/worker/keymanager: retry initialization in case of failure
  ([#2517](https://github.com/oasisprotocol/oasis-core/issues/2517))

  The keymanager worker registers only after the initialization either fails or
  succeeds. In case the worker needs to replicate the first initialization will
  always fail, since other nodes' access control prevents it from replicating.
  In that case the initialization should be retried.

- ias: support for IAS API v4
  ([#2883](https://github.com/oasisprotocol/oasis-core/issues/2883))

  IAS-proxy now proxies to IAS v4 endpoint. Attestation code now works with v4
  IAS API spec.

- common/flags: Fix parsing of metrics.labels, if provided in config .yml
  ([#2905](https://github.com/oasisprotocol/oasis-core/issues/2905))

  [Bug in viper library](https://github.com/spf13/viper/issues/608) was fixed
  upstream and drop-in replacement for `GetStringMapString` was removed.

- staking: Emit events when disbursing fees and rewards
  ([#2909](https://github.com/oasisprotocol/oasis-core/issues/2909))

  Staking events are now generated when disbursing fees and rewards.
  There are two new special account IDs -- `CommonPoolAccountID` and
  `FeeAccumulatorAccountID` (both defined in `go/staking/api/api.go`),
  which are used only in events to signify the common pool and the fee
  accumulator respectively.
  These account IDs are invalid by design to prevent misusing them
  anywhere else.

- runtime: Notify runtimes of its key manager policy updates
  ([#2919](https://github.com/oasisprotocol/oasis-core/issues/2919))

  Before runtimes were unaware of any key-manager policy updates. The runtime
  only queried for the active key-manager policy at startup. This is now changed
  so that the host notifies runtimes of any key-manager policy changes and
  runtime updates the policies.

- go/consensus: Hash user-controlled storage key elements
  ([#2929](https://github.com/oasisprotocol/oasis-core/issues/2929))

- go/oasis-node/cmd/common/metrics: Re-create the pusher on failure
  ([#2936](https://github.com/oasisprotocol/oasis-core/issues/2936))

  When using prometheus' push client, any single failure causes the client
  to be unusable for future requests.  Re-create the client on failure, so
  that metrics might start working again.

- go/oasis-node: Fix parsing of signer configuration
  ([#2950](https://github.com/oasisprotocol/oasis-core/issues/2950))

- go/oasis-node: Make sure the node only tries to stop once
  ([#2964](https://github.com/oasisprotocol/oasis-core/issues/2964))

  This could previously result in a panic during shutdown.

- go/oasis-node: Don't bypass Stop in newNode failure handler
  ([#2966](https://github.com/oasisprotocol/oasis-core/issues/2966))

- go/runtime/host/sandbox: Retry Call in case the runtime is not yet ready
  ([#2967](https://github.com/oasisprotocol/oasis-core/issues/2967))

- go/oasis-node: Properly handle shutdown during startup
  ([#2975](https://github.com/oasisprotocol/oasis-core/issues/2975))

- go/consensus/tendermint: Don't panic on context cancellation
  ([#2982](https://github.com/oasisprotocol/oasis-core/issues/2982))

### Documentation Improvements

- docs: Add documentation around our gRPC over TLS flavor
  ([#2556](https://github.com/oasisprotocol/oasis-core/issues/2556))

- Document all Prometheus metrics produced by `oasis-node`
  ([#2602](https://github.com/oasisprotocol/oasis-core/issues/2602))

  List of metrics including the description, metric type, metric-specific
  labels, and location in the source is now available in
  [docs/oasis-node/metrics.md](../docs/oasis-node/metrics.md) Markdown file. To
  automate generation of this list, a new `go/extra/extract-metric` tool was
  introduced. To update the list of metrics, execute `make update-docs` in the
  project root. Documentation needs to be up to date for `lint` rule to succeed.

### Internal Changes

- ci: Automatically rebuild development/CI Docker images
  ([#295](https://github.com/oasisprotocol/oasis-core/issues/295))

- go: Replace the use of `pkg/error` with `fmt`
  ([#2057](https://github.com/oasisprotocol/oasis-core/issues/2057))

  I also tried to make some of the error messages more consistent but gave
  up when I got to the staking/byzantine node related ones because none of
  them are following our convention.

- go/control: Add IsReady() and WaitReady() RPC methods
  ([#2130](https://github.com/oasisprotocol/oasis-core/issues/2130))

  Beside `IsSynced()` and `WaitSynced()` which are triggered when the consensus
  backend is synced, new `IsReady()` and `WaitReady()` methods have been added
  to the client protocol. These are triggered when all node workers have been
  initialized (including the runtimes) and the hosted processes are ready to
  process requests.

  In addition new `oasis-node debug control wait-ready`
  command was added which blocks the client until the node is ready.

- ci: Add CI test for running E2E tests with IAS development API
  ([#2883](https://github.com/oasisprotocol/oasis-core/issues/2883))

- oasis-test-runner: Refactor initialization of scenario flags
  ([#2897](https://github.com/oasisprotocol/oasis-core/issues/2897))

  Implementations of `Parameters()` function defined in test-runner's scenario
  interface have been revised. All scenario-settable flags are now explicitly
  initialized and scenarios call standard `FlagSet` accessors to fetch
  scenario-specific parameters.

- ci: automatically rety exit status 125 failures
  ([#2900](https://github.com/oasisprotocol/oasis-core/issues/2900))

- go/ias: update test vector to a v4 report
  ([#2901](https://github.com/oasisprotocol/oasis-core/issues/2901))

- go: Bump Go to 1.14.3
  ([#2913](https://github.com/oasisprotocol/oasis-core/issues/2913))

- go: update dependencies depending on `websocket@v1.4.0`
  ([#2927](https://github.com/oasisprotocol/oasis-core/issues/2927))

  Due to a vulnerability in `websocket@1.4.0`: CWE-190.

  Updated libraries:

  - `github.com/libp2p/go-libp2p@v0.1.1` to `github.com/libp2p/go-libp2p@v0.9.1`

  - `github.com/spf13/viper@v1.6.3` to `github.com/spf13/viper@v1.7.0`

  - replace `github.com/gorilla/websocket` with
  `github.com/gorilla/websocket v1.4.2`

- changelog: Add a changelog fragment type for configuration changes
  ([#2952](https://github.com/oasisprotocol/oasis-core/issues/2952))

- runtime-loader: Bump Fortanix EDP crate versions
  ([#2955](https://github.com/oasisprotocol/oasis-core/issues/2955))

  Also bumps Rust nightly to 2020-05-15 as that is required to build the new
  versions.

- go/worker/registration: Add SetAvailableWithCallback to RoleProvider
  ([#2957](https://github.com/oasisprotocol/oasis-core/issues/2957))

  The new method allows the caller to register a callback that will be invoked
  on a successful registration that includes the node descriptor updated by the
  passed hook.

- Transfer oasis-core repository to oasisprotocol
  ([#2968](https://github.com/oasisprotocol/oasis-core/issues/2968))

- ci: don't retry jobs that timeout
  ([#2969](https://github.com/oasisprotocol/oasis-core/issues/2969))

- go: update dynlib dep
  ([#2974](https://github.com/oasisprotocol/oasis-core/issues/2974))

## 20.6 (2020-05-07)

### Removals and Breaking changes

- go/consensus/tendermint: Use MKVS for storing application state
  ([#1898](https://github.com/oasisprotocol/oasis-core/issues/1898))

- `oasis-node`: Refactor `metrics` parameters
  ([#2687](https://github.com/oasisprotocol/oasis-core/issues/2687))

  - `--metrics.push.job_name` renamed to `--metrics.job_name`.
  - `--metrics.push.interval` renamed to `--metrics.interval`.
  - `--metrics.push.instance_label` replaced with more general
    `--metrics.labels` map parameter where `instance` is a required key, if
    metrics are enabled. For example `--metrics.push.instance_label abc` now
    becomes `--metrics.labels instance=abc`. User can also set other
    arbitrary Prometheus labels, for example
    `--metrics.labels instance=abc,cpu=intel_i7-8750`.

- go/consensus/tendermint: Store consensus parameters in ABCI state
  ([#2710](https://github.com/oasisprotocol/oasis-core/issues/2710))

- go: Bump tendermint to v0.33.3-oasis1
  ([#2834](https://github.com/oasisprotocol/oasis-core/issues/2834))

  This is breaking as the tendermint block format has changed.

- go/consensus/genesis: Make max evidence age block and time based
  ([#2834](https://github.com/oasisprotocol/oasis-core/issues/2834))

  - Rename `max_evidence_age` -> `max_evidence_age_blocks`
  - Add `max_evidence_age_time` (default 48h)

  This is obviously breaking.

- keymanager-lib: Bind persisted state to the runtime ID
  ([#2843](https://github.com/oasisprotocol/oasis-core/issues/2843))

  It is likely prudent to bind the persisted master secret to the runtime
  ID.  This change does so by including the key manager runtime ID as the
  AAD when sealing the master secret.

  This is backward incompatible with all current key manager instances as
  the existing persisted master secret will not decrypt.

- go/runtime/enclaverpc: Refactor gRPC endpoint routing
  ([#2844](https://github.com/oasisprotocol/oasis-core/issues/2844))

  Previously each endpoint required its own gRPC service. But since all
  EnclaveRPC requests already include an "endpoint" field, it is better to use
  that for routing requests.

  This commit adds a new enclaverpc.Endpoint interface that is used as an
  endpoint descriptor. All endpoints must be registered in advance (e.g.,
  during init). It also changes the key manager EnclaveRPC support to use the
  new API.

- `oasis-net-runner`: `--net.*` flags renamed to `--fixture.default.*`
  ([#2848](https://github.com/oasisprotocol/oasis-core/issues/2848))

  For example `--net.node.binary mynode/oasis-node` becomes
  `--fixture.default.node.binary mynode/oasis-node`.

- go/consensus: Stake weighted voting
  ([#2868](https://github.com/oasisprotocol/oasis-core/issues/2868))

  That is, validator voting power proportional to entity stake
  (previously: "flat" all-validators-equal voting power).
  Radical!

- go/common/node: Add RoleConsensusRPC role bit
  ([#2881](https://github.com/oasisprotocol/oasis-core/issues/2881))

### Features

- go/worker/consensusrpc: Add public consensus RPC services worker
  ([#2440](https://github.com/oasisprotocol/oasis-core/issues/2440))

  A public consensus services worker enables any full consensus node to expose
  light client services to other nodes that may need them (e.g., they are needed
  to support light clients).

  The worker can be enabled using `--worker.consensusrpc.enabled` and is
  disabled by default. Enabling the public consensus services worker exposes
  the light consensus client interface over publicly accessible gRPC.

- go/consensus: Add basic API for supporting light consensus clients
  ([#2440](https://github.com/oasisprotocol/oasis-core/issues/2440))

- `oasis-node`: Add benchmarking utilities
  ([#2687](https://github.com/oasisprotocol/oasis-core/issues/2687))

  - New Prometheus metrics for:
    - datadir space usage,
    - I/O (read/written bytes),
    - memory usage (VMSize, RssAnon, RssFile, RssShmem),
    - CPU (utime and stime),
    - network interfaces (rx/tx bytes/packets),
  - Bumps `prometheus/go_client` to latest version which fixes sending label
    values containing non-url characters.
  - Bumps `spf13/viper` which fixes `IsSet()` behavior.

- Add `GetEvents` to backends
  ([#2778](https://github.com/oasisprotocol/oasis-core/issues/2778))

  The new `GetEvents` call returns all events at a specific height,
  without having to watch for them using the `Watch*` methods.
  It is currently implemented for the registry, roothash, and staking
  backends.

- go/keymanager/api: Add a gRPC endpoint for status queries
  ([#2843](https://github.com/oasisprotocol/oasis-core/issues/2843))

  Mostly so that the test cases can query statuses.

- go/oasis-test-runner/oasis: Add a keymanager replication test
  ([#2843](https://github.com/oasisprotocol/oasis-core/issues/2843))

- `oasis-net-runner`: Add support for fixtures in JSON file
  ([#2848](https://github.com/oasisprotocol/oasis-core/issues/2848))

  New flag `--fixture.file` allows user to load default fixture from JSON file.
  In addition `dump-fixture` command dumps configured JSON-encoded fixture to
  standard output which can serve as a template.

- go/consensus/tendermint: Expose new config options added in Tendermint 0.33
  ([#2855](https://github.com/oasisprotocol/oasis-core/issues/2855))

  Tendermint 0.33 added the concept of unconditional P2P peers. Support for
  setting the unconditional peers via `tendermint.p2p.unconditional_peer_ids`
  configuration flag is added. On sentry node, upstream nodes will automatically
  be set as unconditional peers.

  Tendermint 0.33 added support for setting maximum re-dial period when
  dialing persistent peers. This adds support for setting the period via
  `tendermint.p2p.persistent_peers_max_dial_period` flag.

- go/consensus/tendermint: Signal RetainHeight on Commit
  ([#2863](https://github.com/oasisprotocol/oasis-core/issues/2863))

  This allows Tendermint Core to discard data for any heights that were pruned
  from application state.

- go/consensus/tendermint: Bump Tendermint Core to 0.33.4
  ([#2863](https://github.com/oasisprotocol/oasis-core/issues/2863))

- go/consensus/tendermint: sync-worker additionally check block timestamps
  ([#2873](https://github.com/oasisprotocol/oasis-core/issues/2873))

  Sync-worker relied on Tendermint fast-sync to determine if the node is still
  catching up. This PR adds aditional condition that the latest block is not
  older than 1 minute. This prevents cases where node would report as caught up
  after stopping fast-sync, but before it has actually caught up.

- go/consensus: Add GetGenesisDocument
  ([#2889](https://github.com/oasisprotocol/oasis-core/issues/2889))

  The consensus client now has a new method to return the original
  genesis document.

- go/staking: Add event hashes
  ([#2889](https://github.com/oasisprotocol/oasis-core/issues/2889))

  Staking events now have a new `TxHash` field, which contains
  the hash of the transaction that caused the event (or the empty
  hash in case of block events).

### Bug Fixes

- go: Extract and generalize registry's staking sanity checks
  ([#2748](https://github.com/oasisprotocol/oasis-core/issues/2748))

  Augment the checks to check if an entity has enough stake for all stake claims
  in the Genesis document to prevent panics at oasis-node start-up due to
  entities not having enough stake in the escrow to satisfy all their stake
  claims.

- go/oasis-node/cmd/ias: Fix WatchRuntimes retry
  ([#2832](https://github.com/oasisprotocol/oasis-core/issues/2832))

  Previously the IAS proxy could incorrectly panic during shutdown when the
  context was cancelled.

- go/worker/keymanager: Add an enclave rpc handler
  ([#2843](https://github.com/oasisprotocol/oasis-core/issues/2843))

- go/worker/keymanager: Actually allow replication to maybe work
  ([#2843](https://github.com/oasisprotocol/oasis-core/issues/2843))

  Access control forbidding replication may be more secure, but is not all
  that useful.

- go/keymanager/client: Support km->km connections
  ([#2843](https://github.com/oasisprotocol/oasis-core/issues/2843))

- go/common/crypto/mrae/deoxysii: Use SHA512/256 for the KDF
  ([#2853](https://github.com/oasisprotocol/oasis-core/issues/2853))

  Following 73aacaa73d7116a6be0443e70f2d10d0c7a4b76e, this should also use
  the correct hash algorithm for the KDF.

- go/extra/stats: fix & simplify node-entity mapping
  ([#2856](https://github.com/oasisprotocol/oasis-core/issues/2856))

  Instead of separately querying for entities and nodes, we can get Entity IDs
  from nodes directly.

  This change also fixes a case that previous variant missed: node that was
  removed from entity list of nodes, but has not yet expired.

- go/extra/stats: fix heights at which missing nodes should be queried
  ([#2858](https://github.com/oasisprotocol/oasis-core/issues/2858))

  If a missing signature is encountered, the registry should be queried at
  previous height, since that is the height at which the vote was made.

- client/rpc: Change session identifier on reset
  ([#2872](https://github.com/oasisprotocol/oasis-core/issues/2872))

  Previously the EnclaveRPC client did not change the session identifier on
  reset, resulting in unnecessary round-trips during a transport error. The
  EnclaveRPC client now changes the session identifier whenever resetting the
  session.

- go/worker/storage: Correctly apply genesis storage state
  ([#2874](https://github.com/oasisprotocol/oasis-core/issues/2874))

  Previously genesis storage state was only applied at consensus genesis which
  did not support dynamically registered runtimes. Now genesis state is
  correctly applied when the storage node initializes for the first time (e.g.,
  when it sees the registered runtime).

  This also removes the now unused RegisterGenesisHook method from the
  consensus backend API.

- worker/registration: use WatchLatestEpoch when watching for registrations
  ([#2876](https://github.com/oasisprotocol/oasis-core/issues/2876))

  By using WatchLatestEpoch the worker will always try to register for latest
  known epoch, which should prevent cases where registration worker fell behind
  and was trying to register for past epochs.

- go/runtime/client: Actually store the created key manager client
  ([#2885](https://github.com/oasisprotocol/oasis-core/issues/2885))

- go/runtime/committee: Restore previously picked node in RR selection
  ([#2885](https://github.com/oasisprotocol/oasis-core/issues/2885))

  Previously the round-robin node selection policy would randomize the order on
  every update ignoring the currently picked node. This would cause the current
  node to flip on each update causing problems with EnclaveRPC which is
  stateful.

  The fix makes the round-robin node selection policy attempt to restore the
  currently picked node on each update. This means that in case the node is
  still in the node list, it will not change.

- go/scheduler: Increase tokens per voting power
  ([#2892](https://github.com/oasisprotocol/oasis-core/issues/2892))

  We'll need this to fit under tendermint's maximum total voting power
  limit.

### Documentation improvements

- Refactor documentation, add architecture overview
  ([#2791](https://github.com/oasisprotocol/oasis-core/issues/2791))

### Internal changes

- `oasis-test-runner`: Add benchmarking utilities
  ([#2687](https://github.com/oasisprotocol/oasis-core/issues/2687))

  - `oasis-test-runner` now accepts `--metrics.address` and `--metrics.interval`
    parameters which are forwarded to `oasis-node` workers.
  - `oasis-test-runner` now signals `oasis_up` metric to Prometheus when a test
    starts and when it finishes.
  - `--num_runs` parameter added which specifies how many times each test should
    be run.
  - `basic` E2E test was renamed to `runtime`.
  - Scenario names now use corresponding namespace. e.g. `halt-restore` is now
    `e2e/runtime/halt-restore`.
  - Scenario parameters are now exposed and settable via CLI by reimplementing
    `scenario.Parameters()` and setting it with `--<test_name>.<param>=<val>`.
  - Scenario parameters can also be generally set, for example
    `--e2e.node.binary` will set `node.binary` parameter for all E2E tests and
    `--e2e/runtime.node.binary` will set it for tests which inherit `runtime`.
  - Multiple parameter values can be provided in form
    `--<test_name>.<param>=<val1>,<val2>,...`. In this case, `oasis-test-runner`
    combines them with other parameters and generates unique parameter sets for
    each test.
  - Each scenario is run in a unique datadir per parameter set of form
    `oasis-test-runnerXXXXXX/<test_name>/<run_id>`.
  - Due to very long datadir for some e2e tests, custom internal gRPC socket
    names are provided to `oasis-node`.
  - If metrics are enabled, new labels are passed to oasis-nodes and pushed to
    Prometheus for each test:
    - `instance`,
    - `run`,
    - `test`,
    - `software_version`,
    - `git_branch`,
    - whole test-specific parameter set.
  - New `version.GitBranch` variable determined and set during compilation.
  - Current parameter set, run number, and test name dumped to `test_info.json`
    in corresponding datadir. This is useful when packing whole datadir for
    external debugging.
  - New `cmp` command for analyzing benchmark results has been added which
    fetches the last two batches of benchmark results from Prometheus and
    compares them. For more information, see `README.md` in
    `go/oasis-test-runner` folder.

- ci: New benchmarks pipeline has been added
  ([#2687](https://github.com/oasisprotocol/oasis-core/issues/2687))

  `benchmarks.pipeline.yml` runs all E2E tests and compares the benchmark
  results from the previous batch using the new `oasis-test-runner cmp` command.

- `oasis-node`: Add custom internal socket path flag (for E2E tests only!)
  ([#2687](https://github.com/oasisprotocol/oasis-core/issues/2687))

  `--debug.grpc.internal.socket_name` flag was added which forces `oasis-node`
  to use the given path for the internal gRPC socket. This was necessary,
  because some E2E test names became very lengthy and original datadir exceeded
  the maximum unix socket path length. `oasis-test-runner` now generates
  shorter socket names in `/tmp/oasis-test-runnerXXXXXX` directory and provides
  them to `oasis-node`. **Due to security risks never ever use this flag in
  production-like environments. Internal gRPC sockets should always reside in
  node datadir!**

- go/registry/api: Extend `NodeLookup` and `RuntimeLookup` interfaces
  ([#2748](https://github.com/oasisprotocol/oasis-core/issues/2748))

  Define `Nodes()` and `AllRuntimes()` methods.

- go/staking/tests: Add escrow and delegations to debug genesis state
  ([#2767](https://github.com/oasisprotocol/oasis-core/issues/2767))

  Introduce `stakingTestsState` that holds the current state of staking
  tests and enable the staking implementation tests
  (`StakingImplementationTest`, `StakingClientImplementationTests`) to always
  use this up-to-date state.

- go/runtime/committee: Don't close gRPC connections on connection refresh
  ([#2826](https://github.com/oasisprotocol/oasis-core/issues/2826))

- go: Refactor E2E coverage integration test wrapper
  ([#2832](https://github.com/oasisprotocol/oasis-core/issues/2832))

  This makes it possible to easily have E2E coverage instrumented binaries for
  things other than oasis-node.

- go/oasis-node: Move storage benchmark subcommand under debug
  ([#2832](https://github.com/oasisprotocol/oasis-core/issues/2832))

- keymanager-runtime: replace with test/simple-keymanager
  ([#2837](https://github.com/oasisprotocol/oasis-core/issues/2837))

  Common keymanager initalization code is extracted into the keymanager-lib
  crate. This enables for the actual key manager implementation to only
  provide a set of key manager policy signers.
  Aditionally the `keymanager-runtime` crate is removed and replaced with
  a test `simple-keymanager` runtime that is used in E2E tests.

- docker: remove docker image build pipelines and cleanup testing image
  ([#2838](https://github.com/oasisprotocol/oasis-core/issues/2838))

- go/oasis-test-runner: Generate a new random seed on each run
  ([#2849](https://github.com/oasisprotocol/oasis-core/issues/2849))

- go/storage/mkvs/checkpoint: Refactor restorer interface
  ([#2860](https://github.com/oasisprotocol/oasis-core/issues/2860))

- go/storage/mkvs/checkpoint: Add common checkpointer implementation
  ([#2860](https://github.com/oasisprotocol/oasis-core/issues/2860))

  Previously there was a checkpointer implemented in the storage worker
  but since this may be useful in multiple places, the checkpointer
  implementation is generalized and moved to the checkpoint package.

- go/oasis-test-runner: Configure consensus state pruning
  ([#2866](https://github.com/oasisprotocol/oasis-core/issues/2866))

- go: Start using new protobuf module location
  ([#2867](https://github.com/oasisprotocol/oasis-core/issues/2867))

  The previous location has been deprecated.

- go/common/pubsub: support subscriptions based on bounded ring channels
  ([#2876](https://github.com/oasisprotocol/oasis-core/issues/2876))

- go/epochtime: add WatchLatestEpoch method
  ([#2876](https://github.com/oasisprotocol/oasis-core/issues/2876))

  The method is similar to the existing WatchEpochs method, with the change that
  unread epochs get overridden with latest epoch.

- go/common/crypto/hash: Add NewFrom and NewFromBytes functions
  ([#2890](https://github.com/oasisprotocol/oasis-core/issues/2890))

- ci: automatically retry jobs due to host agent failures
  ([#2894](https://github.com/oasisprotocol/oasis-core/issues/2894))

## 20.5 (2020-04-10)

### Process

- Include oasis-core-runtime-loader and oasis-net-runner in releases
  ([#2780](https://github.com/oasisprotocol/oasis-core/issues/2780))

### Removals and Breaking changes

- storage: Rename "round" to "version"
  ([#2734](https://github.com/oasisprotocol/oasis-core/issues/2734))

  Previously the MKVS used the term "round" to mean a monotonically increasing
  version number. This choice was due to the fact that it was initially used to
  only store runtime state which has a concept of rounds.

  As we expand its use it makes more sense to generalize this and call it
  version.

- go staking: Remove locked accounts
  ([#2753](https://github.com/oasisprotocol/oasis-core/issues/2753))

  We expect not to need this feature.

- go/consensus: Introduce gas cost based on tx size
  ([#2761](https://github.com/oasisprotocol/oasis-core/issues/2761))

- storage/mkvs: Only nil value should mean deletion
  ([#2775](https://github.com/oasisprotocol/oasis-core/issues/2775))

  Previously an empty value in the write log signalled that the given entry is a
  delete operation instead of an insert one. This was incorrect as inserting an
  empty byte string is allowed. The value is now wrapped in an `Option`, with
  `None` (`nil` in Go) meaning delete and `Some(vec![])` (`[]byte{}` in Go)
  meaning insert empty value.

  This change is BREAKING as it changes write log semantics and thus it breaks
  the runtime worker-host protocol.

- go/staking: include LastBlockFees in genesis
  ([#2777](https://github.com/oasisprotocol/oasis-core/issues/2777))

  Previosuly last block fees in the block of the genesis dump were lost. In the
  case when these fees were non-zero this also caused a missmatch in total token
  supply. Last block fees are now exported and during initialization of the new
  chain moved to the common pool.

- go/staking: Three-way fee split
  ([#2794](https://github.com/oasisprotocol/oasis-core/issues/2794))

  We should give more to the previous block proposer, which is the block
  that first ran the transactions that paid the fees in the
  `LastBlockFees`.
  Currently they only get paid as a voter.

  See
  [oasis-core#2794](https://github.com/oasisprotocol/oasis-core/pull/2794)
  for a description of the new fee split.

  Instructions for genesis document maintainers:

  1. Rename `fee_split_vote` to `fee_split_weight_vote` and
     `fee_split_propose` to `fee_split_weight_next_propose` and
     add `fee_split_weight_propose` in `.staking.params`.

### Features

- node: Add automatic TLS certificate rotation support
  ([#2098](https://github.com/oasisprotocol/oasis-core/issues/2098))

  It is now possible to automatically rotate the node's TLS
  certificates every N epochs by passing the command-line flag
  `worker.registration.rotate_certs`.
  Do not use this option on sentry nodes or IAS proxies.

- go/storage/mkvs: Use Badger to manage versions
  ([#2674](https://github.com/oasisprotocol/oasis-core/issues/2674))

  By restricting how Prune behaves (it can now only remove the earliest round)
  we can leverage Badger's managed mode to have it manage versions for us. This
  avoids the need to track node lifetimes separately.

- go/common/crypto/signature/signer/composite: Initial import
  ([#2684](https://github.com/oasisprotocol/oasis-core/issues/2684))

  This adds a composite signer factory that can aggregate multiple signer
  factories.  This could be used (for example), to use multiple signer
  backends simultaneously, depending on the key role.

  Eg: The P2P link signer could use a local file, while the consensus
  signer can be backed by a remote HSM.

- e2e tests: Test debonding entries from genesis
  ([#2747](https://github.com/oasisprotocol/oasis-core/issues/2747))

  Here's an e2e test scenario that exercises debonding delegation records
  from the genesis document.

- Add support for custom runtime dispatchers
  ([#2749](https://github.com/oasisprotocol/oasis-core/issues/2749))

  This reorganizes the dispatching code to work with a trait rather than a
  concrete dispatcher object, enabling runtimes to have their own
  dispatchers.

- txsource: delegation workload
  ([#2752](https://github.com/oasisprotocol/oasis-core/issues/2752))

- txsource: add a runtime workload
  ([#2759](https://github.com/oasisprotocol/oasis-core/issues/2759))

  The added runtime workload submits simiple-keyvalue runtime requests.

- go/txsource: add a commission schedule amendments workload
  ([#2766](https://github.com/oasisprotocol/oasis-core/issues/2766))

  The added workload generated commission schedule amendment requests.

- go/staking: add LastBlockFees query method
  ([#2769](https://github.com/oasisprotocol/oasis-core/issues/2769))

  LastBlockFees returns the collected fees for previous block.

- txsource/queries: workload doing historical queries
  ([#2769](https://github.com/oasisprotocol/oasis-core/issues/2769))

  Queries workload continuously performs various historic queries using the
  exposed APIs and makes sure the responses make sense.

- go/txsource/transfer: inlcude burn transactions in transfer workload
  ([#2773](https://github.com/oasisprotocol/oasis-core/issues/2773))

- go/oasis-node/cmd/debug/consim: Initial import
  ([#2784](https://github.com/oasisprotocol/oasis-core/issues/2784))

  Add the ability to exercise some backends without tendermint, while
  attempting to preserve some of the semantics.

- go/runtime/client: expose GetGenesisBlock method in runtime client
  ([#2796](https://github.com/oasisprotocol/oasis-core/issues/2796))

### Bug Fixes

- staking/state: fix DelegationsFor queries
  ([#2756](https://github.com/oasisprotocol/oasis-core/issues/2756))

  DelegationFor and DebondingDelegationsFor would stop traversing the state to
  soon in some cases.

- staking/api/commission: fix possible panic in validation check
  ([#2763](https://github.com/oasisprotocol/oasis-core/issues/2763))

  The validation check would panic whenever the number of bound steps was
  greater than `rate_steps + 2`.

- go/storage/mkvs: Don't forget to include siblings in SyncGet proof
  ([#2775](https://github.com/oasisprotocol/oasis-core/issues/2775))

- storage/mkvs: Don't try to sync dirty keys
  ([#2775](https://github.com/oasisprotocol/oasis-core/issues/2775))

- go/storage/client: Refresh connections when retrying
  ([#2783](https://github.com/oasisprotocol/oasis-core/issues/2783))

  Previously the storage client did not refresh connections on each retry, so in
  case a committee change happened while an operation was in progress, all
  operations continued to use the old connection (which was closed) and thus
  failed. We now refresh connections on each retry.

- go/storage/client: Don't treat "no nodes" as a permanent error
  ([#2785](https://github.com/oasisprotocol/oasis-core/issues/2785))

- go/consensus/tendermint: Use our notion of latest height
  ([#2786](https://github.com/oasisprotocol/oasis-core/issues/2786))

  Do not let Tendermint determine the latest height as that completely ignores
  ABCI processing so it can return a block for which local state does not yet
  exist.

- go/runtime/client: use history for GetBlock(latest)
  ([#2795](https://github.com/oasisprotocol/oasis-core/issues/2795))

  Using history for all GetBlock requests prevents the case where the latest
  block would already be available but not yet in history, leading to
  inconsistent results compared to querying by specific block number.

- go/storage/mkvs: Use cbor.UnmarshalTrusted for internal metadata
  ([#2800](https://github.com/oasisprotocol/oasis-core/issues/2800))

- go/consensus: Shorten gas import
  ([#2802](https://github.com/oasisprotocol/oasis-core/issues/2802))

  Switch to more concise `FromUint64`.

- go/consensus/tendermint/apps/staking: Propagate error in initTotalSupply
  ([#2809](https://github.com/oasisprotocol/oasis-core/issues/2809))

- go/staking: Use uint16 for limits in CommissionScheduleRules
  ([#2810](https://github.com/oasisprotocol/oasis-core/issues/2810))

- go/txsource/queries: Wait for indexed blocks before GetBlockByHash
  ([#2814](https://github.com/oasisprotocol/oasis-core/issues/2814))

- go/worker/registration: Fix crash when failing to query sentry addresses
  ([#2825](https://github.com/oasisprotocol/oasis-core/issues/2825))

- go/consensus/tendermint: Bump Tendermint Core to 0.32.10
  ([#2833](https://github.com/oasisprotocol/oasis-core/issues/2833))

### Documentation improvements

- README: Update Rust-related installation instructions
  ([#2745](https://github.com/oasisprotocol/oasis-core/issues/2745))

### Internal changes

- Move storage/mkvs/urkel to just storage/mkvs
  ([#2657](https://github.com/oasisprotocol/oasis-core/issues/2657))

  The MKVS implementation has been changed from the initial "Urkel tree"
  structure and it is no longer an actual "Urkel tree" so having "urkel" in its
  name is just confusing.

- runtime: Add hongfuzz fuzzing targets
  ([#2705](https://github.com/oasisprotocol/oasis-core/issues/2705))

- go/staking/api: Add more details to sanity check errors
  ([#2760](https://github.com/oasisprotocol/oasis-core/issues/2760))

- Make: Allow running Go unit tests and node tests independently
  ([#2776](https://github.com/oasisprotocol/oasis-core/issues/2776))

  They can be run using the new `test-unit` and `test-node` targets.

- txsource/workload/queries: Add num last kept versions argument
  ([#2783](https://github.com/oasisprotocol/oasis-core/issues/2783))

- go/runtime/client: Use prefetch (GetTransactionMultiple) in QueryTxs
  ([#2783](https://github.com/oasisprotocol/oasis-core/issues/2783))

  Previously if multiple transactions in the same block were returned as
  QueryTxs results, each transaction was queried independently, resulting in
  multiple round trips. Now we use GetTransactionMultiple to prefetch multiple
  transactions in a single round trip which should improve latency.

- txsource/queries: increase the odds of querying the latest height
  ([#2787](https://github.com/oasisprotocol/oasis-core/issues/2787))

- go/txsource/queries: obtain earliest runtime round from runtime genesis
  ([#2796](https://github.com/oasisprotocol/oasis-core/issues/2796))

- go/common/cbor: Add UnmarshalTrusted for trusted inputs
  ([#2800](https://github.com/oasisprotocol/oasis-core/issues/2800))

  The new method relaxes some decoding restrictions for cases where the inputs
  are trusted (e.g., because they are known to be generated by the local node
  itself).

- oasis-test-runner/txsource: increase number of validators
  ([#2815](https://github.com/oasisprotocol/oasis-core/issues/2815))

  Increase the number of validators used in txsource tests so that consensus can
  keep making progress when one of the nodes is restarted.

- go/consensus/tendermint: support DebugUnsafeReplayRecoverCorruptedWAL
  ([#2815](https://github.com/oasisprotocol/oasis-core/issues/2815))

  Adds support for setting tendermint DebugUnsafeReplayRecoverCorruptedWAL and
  enables it in daily txsource test runs.

- oasis-test-runner/txsource: disable LogAssertNoTimeouts if restarts
  ([#2817](https://github.com/oasisprotocol/oasis-core/issues/2817))

- go/extra/stats: Update availability score formula
  ([#2819](https://github.com/oasisprotocol/oasis-core/issues/2819))

  As per
  </operators/the-quest-rules.html#types-of-challenges>,
  the availability score formula has changed from "Blocks Signed + 50 x Blocks
  Proposed" to "Blocks Signed + 50 x Blocks Proposed in Round 0".

- oasis-test-runner/txsource: disable Merge Discrepancy checker
  ([#2821](https://github.com/oasisprotocol/oasis-core/issues/2821))

  Timeout due to validator restarting also causes a merge discrepancy. Since
  timeouts can happen, also disable the Merge discrepancy checker.

- go/runtime/committee: Introduce close delay when rotating connections
  ([#2822](https://github.com/oasisprotocol/oasis-core/issues/2822))

  Previously a connection was immediately closed, interrupting any in-flight
  requests. This introduces a configurable (via WithCloseDelay option) close
  delay so rotated connections are only closed after some time.

- go/common/grpc: Remove manual resolver hack
  ([#2822](https://github.com/oasisprotocol/oasis-core/issues/2822))

  Since gRPC supports the WithResolvers option to specify local resolvers there
  is no need to use the global resolver registry hack.

- go/runtime/committee: Don't reset committees when they don't change
  ([#2822](https://github.com/oasisprotocol/oasis-core/issues/2822))

  Previously each committee election triggered a reset of all connections for
  that committee. This changes the logic to just bump the committee version in
  case all the committee members are the same.

- tests/fixture/txsources: add initial balance for validator-3
  ([#2830](https://github.com/oasisprotocol/oasis-core/issues/2830))

## 20.4 (2020-03-04)

### Removals and Breaking changes

- go/registry: Enable non-genesis runtime registrations by default
  ([#2406](https://github.com/oasisprotocol/oasis-core/issues/2406))

- Optionally require a deposit for registering a runtime
  ([#2638](https://github.com/oasisprotocol/oasis-core/issues/2638))

- go/staking: Add stateful stake accumulator
  ([#2642](https://github.com/oasisprotocol/oasis-core/issues/2642))

  Previously there was no central place to account for all the parts that need
  to claim some part of an entity's stake which required approximations all
  around.

  This is now changed and a stateful stake accumulator is added to each escrow
  account. The stake accumulator is used to track stake claims from different
  apps (currently only the registry).

  This change also means that node registration will now always require the
  correct amount of stake.

- go/registry: Add explicit EntityID field to Runtime descriptors
  ([#2642](https://github.com/oasisprotocol/oasis-core/issues/2642))

- go/staking: More reward for more signatures
  ([#2647](https://github.com/oasisprotocol/oasis-core/issues/2647))

  We're adjusting fee distribution and the block proposing staking reward to
  incentivize proposers to create blocks with more signatures.

- Send and check expected epoch number during transaction execution
  ([#2650](https://github.com/oasisprotocol/oasis-core/issues/2650))

  Stress tests revealed some race conditions during transaction execution when
  there is an epoch transition. Runtime client now sends `expectedEpochNumber`
  parameter in `SubmitTx` call. The transaction scheduler checks whether the
  expected epoch matches its local one. Additionally, if state transition occurs
  during transaction execution, Executor and Merge committee correctly abort the
  transaction.

- go/staking: Add per-account lockup
  ([#2672](https://github.com/oasisprotocol/oasis-core/issues/2672))

  With this, we'll be able to set up special accounts in the genesis
  document where they're not permitted to transfer staking tokens until
  a the specified epoch time.
  They can still delegate during that time.

- Use `--stake.shares` flag when specifying shares to reclaim from an escrow
  ([#2690](https://github.com/oasisprotocol/oasis-core/issues/2690))

  Previously, the `oasis-node stake account gen_reclaim_escrow` subcommand
  erroneously used the `--stake.amount` flag for specifying the amount of shares
  to reclaim from an escrow.

### Features

- Implement node upgrade mechanism
  ([#2607](https://github.com/oasisprotocol/oasis-core/issues/2607))

  The node now accepts upgrade descriptors which describe the upgrade to carry
  out.

  The node can shut down at the appropriate epoch and then execute any required
  migration handlers on the node itself and on the consensus layer.

  Once a descriptor is submitted, the old node can be normally restarted and
  used until the upgrade epoch is reached; the new binary can not be used at
  all until the old binary has had a chance to reach the upgrade epoch.
  Once that is reached, the old binary will refuse to start.

- go/common/crypto/signature/signers/remote: Add experimental remote signer
  ([#2686](https://github.com/oasisprotocol/oasis-core/issues/2686))

  This adds an experimental remote signer, reference remote signer
  implementation, and theoretically allows the node to be ran with a
  non-file based signer backend.

- go/extra/stats: Figure out how many blocks entities propose
  ([#2693](https://github.com/oasisprotocol/oasis-core/issues/2693))

  Cross reference which node proposed each block and report these
  per-entity as well.

- go/extra/stats: Availability ranking for next Quest phase
  ([#2699](https://github.com/oasisprotocol/oasis-core/issues/2699))

  A new availability score will take into account more than the number of
  block signatures alone.

  This introduces the mechanism to compute a score and print the
  rankings based on that.
  This also implements a provisional scoring formula.

- go/oasis-node/txsource: Add registration workload
  ([#2718](https://github.com/oasisprotocol/oasis-core/issues/2718))

- go/oasis-node/txsource: Add parallel workload
  ([#2724](https://github.com/oasisprotocol/oasis-core/issues/2724))

- go/scheduler: Validators now returns validators by node ID
  ([#2739](https://github.com/oasisprotocol/oasis-core/issues/2739))

  The consensus ID isn't all that useful for most external callers, so
  querying it should just return the validators by node ID instead.

- go/staking: Add a `Delegations()` call, and expose it over gRPC
  ([#2740](https://github.com/oasisprotocol/oasis-core/issues/2740))

  This adds a `Delegations()` call in the spirit of `DebondingDelegations()`
  that returns a map of delegations for a given delegator.

- go/oasis-node/txsource: Use a special account for funding accounts
  ([#2744](https://github.com/oasisprotocol/oasis-core/issues/2744))

  Generate and fund a special account that is used for funding accounts during
  the workload instead of hard-coding funding for fixed addresses.

  Additionally, start using fees and non-zero gas prices in workloads.

### Bug Fixes

- go/storage/client: Retry storage ops on specific errors
  ([#1865](https://github.com/oasisprotocol/oasis-core/issues/1865))

- go/tendermint: Unfatalize seed populating nodes from genesis
  ([#2554](https://github.com/oasisprotocol/oasis-core/issues/2554))

  In some cases we'd prefer to include some nodes in the genesis document
  even when they're registered with an invalid address.

  This makes the seed node ignore those entries and carry on, while
  keeping those entries available for the rest of the system.

- go: Re-enable signature verification disabled for migration
  ([#2615](https://github.com/oasisprotocol/oasis-core/issues/2615))

  Now that the migration has hopefully been done, re-enable all of the
  signature verification that was disabled for the sake of allowing for
  migration.

- go: Don't scan the whole keyspace in badger's tendermint DB implementation
  ([#2664](https://github.com/oasisprotocol/oasis-core/issues/2664))

  When we run off the end of a range iteration.

- runtime: Bump ring to 0.16.11, snow to 0.6.2, Rust to 2020-02-16
  ([#2666](https://github.com/oasisprotocol/oasis-core/issues/2666))

- go/staking/api: Fix genesis sanity check for nonexisting accounts
  ([#2671](https://github.com/oasisprotocol/oasis-core/issues/2671))

  Detect when a (debonding) delegation is specified for a nonexisting account
  and report an appropriate error.

- go/storage/mkvs: Fix iterator bug
  ([#2691](https://github.com/oasisprotocol/oasis-core/issues/2691))

- go/storage/mkvs: Fix bug in `key.Merge` operation with extra bytes
  ([#2698](https://github.com/oasisprotocol/oasis-core/issues/2698))

- go/storage/mkvs: Fix removal crash when key is too short
  ([#2698](https://github.com/oasisprotocol/oasis-core/issues/2698))

- go/storage/mkvs: Fix node unmarshallers
  ([#2703](https://github.com/oasisprotocol/oasis-core/issues/2703))

- go/storage/mkvs: Fix proof verifier
  ([#2703](https://github.com/oasisprotocol/oasis-core/issues/2703))

- go/consensus/tendermint: Properly cache consensus parameters
  ([#2708](https://github.com/oasisprotocol/oasis-core/issues/2708))

- go/badger: Enable truncate to recover from corrupted value log file
  ([#2732](https://github.com/oasisprotocol/oasis-core/issues/2732))

  Apparently badger is not at all resilient to crashes unless the truncate
  option is enabled.

- go/oasis-net-runner/fixtures: Increase scheduler max batch size to 16 MiB
  ([#2741](https://github.com/oasisprotocol/oasis-core/issues/2741))

  This change facilitates RPCs to larger, more featureful runtimes.

- go/common/version: Allow omission of trailing numbers in `parSemVerStr()`
  ([#2742](https://github.com/oasisprotocol/oasis-core/issues/2742))

  Go's [`runtime.Version()`](https://golang.org/pkg/runtime/#Version) function
  can omit the patch number, so augment `parSemVerStr()` to handle that.

### Internal changes

- github: Bump GoReleaser to 0.127.0 and switch back to upstream
  ([#2564](https://github.com/oasisprotocol/oasis-core/issues/2564))

- github: Add new steps to ci-lint workflow
  ([#2572](https://github.com/oasisprotocol/oasis-core/issues/2572),
   [#2692](https://github.com/oasisprotocol/oasis-core/issues/2692),
   [#2717](https://github.com/oasisprotocol/oasis-core/issues/2717))

  Add _Lint git commits_, _Lint Markdown files_, _Lint Change Log fragments_ and
  _Check go mod tidy_ steps to ci-lint GitHub Actions workflow.

  Remove _Lint Git commits_ step from Buildkite's CI pipeline.

- ci: Skip some steps for non-code changes
  ([#2573](https://github.com/oasisprotocol/oasis-core/issues/2573),
   [#2702](https://github.com/oasisprotocol/oasis-core/issues/2702))

  When one makes a pull request that e.g. only adds documentation or
  assembles the Change Log from fragments, all the *heavy* Buildkite
  pipeline steps (e.g. Go/Rust building, Go tests, E2E tests) should be
  skipped.

- go/common/cbor: Bump fxamacker/cbor to v2.2
  ([#2635](https://github.com/oasisprotocol/oasis-core/issues/2635))

- go/storage/mkvs: Fuzz storage proof decoder
  ([#2637](https://github.com/oasisprotocol/oasis-core/issues/2637))

- ci: merge coverage files per job
  ([#2644](https://github.com/oasisprotocol/oasis-core/issues/2644))

- go/oasis-test-runner: Update multiple-runtimes E2E test
  ([#2650](https://github.com/oasisprotocol/oasis-core/issues/2650))

  Reduce all group sizes to 1 with no backups, use `EpochtimeMock` to avoid
  unexpected blocks, add `numComputeWorkers` parameter.

- Replace redundant fields with `Consensus` accessors
  ([#2650](https://github.com/oasisprotocol/oasis-core/issues/2650))

  `Backend` in `go/consensus/api` contains among others accessors for
  `Beacon`, `EpochTime`, `Registry`, `RootHash`, `Scheduler`, and
  `KeyManager`. Use those instead of direct references. The following
  structs were affected:

  - `Node` in `go/cmd/node`,
  - `Node` in `go/common/committee`,
  - `Worker` in `go/common`,
  - `clientCommon` in `go/runtime/client`,
  - `Group` in `go/worker/common/committee`.

- go/storage: Refactor checkpointing interface
  ([#2659](https://github.com/oasisprotocol/oasis-core/issues/2659))

  Previously the way storage checkpoints were implemented had several
  drawbacks, namely:

  - Since the checkpoint only streamed key/value pairs this prevented
    correct tree reconstruction as tree nodes also include a `Round` field
    which specifies the round at which a given tree node was created.

  - While old checkpoints were streamed in chunks and thus could be
    resumed or streamed in parallel from multiple nodes, there was no
    support for verifying the integrity of a single chunk.

  This change introduces an explicit checkpointing mechanism with a simple
  file-based backend reference implementation. The same mechanism could
  also be used in the future with Tendermint's app state sync proposal.

- changelog: Use Git commit message style for Change Log fragments
  ([#2662](https://github.com/oasisprotocol/oasis-core/issues/2662))

  For more details, see the description in [Change Log fragments](
  .changelog/README.md).

- Make: Add lint targets
  ([#2662](https://github.com/oasisprotocol/oasis-core/issues/2662),
   [#2692](https://github.com/oasisprotocol/oasis-core/issues/2692))

  Add a general `lint` target that depends on the following lint targets:

  - `lint-go`: Lint Go code,
  - `lint-git`: Lint git commits,
  - `lint-md`: Lint Markdown files (except Change Log fragments),
  - `lint-changelog`: Lint Change Log fragments.

- Add sanity checks for stake accumulator state integrity
  ([#2665](https://github.com/oasisprotocol/oasis-core/issues/2665))

- go/consensus/tendermint: Don't use `UnsafeSigner`
  ([#2670](https://github.com/oasisprotocol/oasis-core/issues/2670))

- rust: Update ed25519-dalek and associated dependencies
  ([#2678](https://github.com/oasisprotocol/oasis-core/issues/2678))

  This change updates ed25519-dalek, rand and x25519-dalek.

- Bump minimum Go version to 1.13.8
  ([#2689](https://github.com/oasisprotocol/oasis-core/issues/2689))

- go/storage/mkvs: Add overlay tree to support rolling back state
  ([#2691](https://github.com/oasisprotocol/oasis-core/issues/2691))

- go/storage/mkvs: Make `Tree` an interface
  ([#2691](https://github.com/oasisprotocol/oasis-core/issues/2691))

- gitlint: Require body length of at least 20 characters (if body exists)
  ([#2692](https://github.com/oasisprotocol/oasis-core/issues/2692))

- Make build-fuzz work again, test it on CI
  ([#2695](https://github.com/oasisprotocol/oasis-core/issues/2695))

- changelog: Reference multiple issues/pull requests for a single entry
  ([#2697](https://github.com/oasisprotocol/oasis-core/issues/2697))

  For more details, see the description in [Change Log fragments](
  .changelog/README.md#multiple-issues--pull-requests-for-a-single-fragment).

- go/storage/mkvs: Add MKVS fuzzing
  ([#2698](https://github.com/oasisprotocol/oasis-core/issues/2698))

- github: Don't trigger ci-reproducibility workflow for pull requests
  ([#2704](https://github.com/oasisprotocol/oasis-core/issues/2704))

- go/oasis-test-runner: Improve txsource E2E test
  ([#2709](https://github.com/oasisprotocol/oasis-core/issues/2709))

  This adds the following general txsource scenario features:

  - Support for multiple parallel workloads.
  - Restart random nodes on specified interval.
  - Ensure consensus liveness for the duration of the test.

  It also adds an oversized txsource workload which submits oversized
  transactions periodically.

- go/consensus/tendermint: Expire txes when CheckTx is disabled
  ([#2720](https://github.com/oasisprotocol/oasis-core/issues/2720))

  When CheckTx is disabled (for debug purposes only, e.g. in E2E tests), we
  still need to periodically remove old transactions as otherwise the mempool
  will fill up. Keep track of transactions were added and invalidate them when
  they expire.

- runtime: Remove the non-webpki/snow related uses of ring
  ([#2733](https://github.com/oasisprotocol/oasis-core/issues/2733))

  As much as I like the concept of ring as a library, and the
  implementation, the SGX support situation is ridiculous, and we should
  minimize the use of the library for cases where alternatives exist.

## 20.3 (2020-02-06)

### Removals and Breaking changes

- Add gRPC Sentry Nodes support
  ([#1829](https://github.com/oasisprotocol/oasis-core/issues/1829))

  This adds gRPC proxying and policy enforcement support to existing sentry
  nodes, which enables protecting upstream nodes' gRPC endpoints.

  Added/changed flags:

  - `worker.sentry.grpc.enabled`: enables the gRPC proxy (requires
    `worker.sentry.enabled` flag)
  - `worker.sentry.grpc.client.port`: port on which gRPC proxy is accessible
  - `worker.sentry.grpc.client.address`: addresses on which gRPC proxy is
    accessible (needed so protected nodes can query sentries for its addresses)
  - `worker.sentry.grpc.upstream.address`: address of the protected node
  - `worker.sentry.grpc.upstream.cert`: public certificate of the upstream grpc
    endpoint
  - `worker.registration.sentry.address` renamed back to `worker.sentry.address`
  - `worker.registration.sentry.cert_file` renamed back to
    `worker.sentry.cert_file`

- go/common/crypto/tls: Use ed25519 instead of P-256
  ([#2058](https://github.com/oasisprotocol/oasis-core/issues/2058))

  This change is breaking as the old certificates are no longer supported,
  and they must be regenerated.  Note that this uses the slower runtime
  library ed25519 implementation instead of ours due to runtime library
  limitations.

- All marshalable enumerations in the code were checked and the default
  `Invalid = 0` value was added, if it didn't exist before
  ([#2546](https://github.com/oasisprotocol/oasis-core/issues/2546))

  This makes the code less error prone and more secure, because it requires
  the enum field to be explicitly set, if some meaningful behavior is expected
  from the corresponding object.

- go/registry: Add `ConsensusParams.MaxNodeExpiration`
  ([#2580](https://github.com/oasisprotocol/oasis-core/issues/2580))

  Node expirations being unbound is likely a bad idea.  This adds a
  consensus parameter that limits the maximum lifespan of a node
  registration, to a pre-defined number of epochs (default 5).

  Additionally the genesis document sanity checker is now capable of
  detecting if genesis node descriptors have invalid expirations.

  Note: Existing deployments will need to alter the state dump to
  configure the maximum node expiration manually before a restore
  will succeed.

- go/common/crypto/signature: Use base64-encoded IDs/public keys
  ([#2588](https://github.com/oasisprotocol/oasis-core/issues/2588))

  Change `String()` method to return base64-encoded representation of a public
  key instead of the hex-encoded representation to unify CLI experience when
  passing/printing IDs/public keys.

- go/registry: Disallow entity signed node registrations
  ([#2594](https://github.com/oasisprotocol/oasis-core/issues/2594))

  This feature is mostly useful for testing and should not be used in
  production, basically ever.  Additionally, when provisioning node
  descriptors, `--node.is_self_signed` is now the default.

  Note: Breaking if anyone happens to use said feature, but enabling said
  feature is already feature-gated, so this is unlikely.

- go/registry: Ensure that node descriptors are signed by all public keys
  ([#2599](https://github.com/oasisprotocol/oasis-core/issues/2599))

  To ensure that nodes demonstrate proof that they posses the private keys
  for all public keys contained in their descriptor, node descriptors now
  must be signed by the node, consensus, p2p and TLS certificate key.

  Note: Node descriptors generated prior to this change are now invalid and
  will be rejected.

- Rewards and fees consensus parameters
  ([#2624](https://github.com/oasisprotocol/oasis-core/issues/2624))

  Previously things like reward "factors" and fee distribution "weights" were
  hardcoded. But we have pretty good support for managing consensus parameters,
  so we ought to move them there.

- Special rewards for block proposer
  ([#2625](https://github.com/oasisprotocol/oasis-core/issues/2625))

  - a larger portion of the fees
  - an additional reward

- go/consensus/tendermint: mux offset block height consistently
  ([#2634](https://github.com/oasisprotocol/oasis-core/issues/2634))

  We've been using `blockHeight+1` for getting the epoch time except for on
  blockHeight=1.
  The hypothesis in this change is that we don't need that special case.

- Tendermint P2P configuration parameters
  ([#2646](https://github.com/oasisprotocol/oasis-core/issues/2646))

  This allows configuring P2P parameters:
  - `MaxNumInboundPeers`,
  - `MaxNumOutboundPeers`,
  - `SendRate` and
  - `RecvRate`

  through their respective CLI flags:
  - `tendermint.p2p.max_num_inbound_peers`,
  - `tendermint.p2p.max_num_outbound_peers`,
  - `tendermint.p2p.send_rate`, and
  - `tendermint.p2p.recv_rate`.

  It also increases the default value of `MaxNumOutboundPeers` from 10 to 20 and
  moves all P2P parameters under the `tendermint.p2p.*` namespace.

- Add `oasis-node identity tendermint show-{node,consensus}-address` subcommands
  ([#2649](https://github.com/oasisprotocol/oasis-core/issues/2649))

  The `show-node-address` subcommmand returns node's public key converted to
  Tendermint's address format.
  It replaces the `oasis-node debug tendermint show-node-id` subcommand.

  The `show-consensus-address` subcommand returns node's consensus key converted
  to Tendermint's address format.

### Features

- Refresh node descriptors mid-epoch
  ([#1794](https://github.com/oasisprotocol/oasis-core/issues/1794))

  Previously node descriptors were only refreshed on an epoch transition which
  meant that any later updates were ignored until the next epoch.
  This caused stale RAKs to stay in effect when runtime restarts happened,
  causing attestation verification to fail.

  Enabling mid-epoch refresh makes nodes stay up to date with committee member
  node descriptor updates.

- go/worker/storage: Add configurable limits for storage operations
  ([#1914](https://github.com/oasisprotocol/oasis-core/issues/1914))

- Flexible key manager policy signers
  ([#2444](https://github.com/oasisprotocol/oasis-core/issues/2444))

  The key manager runtime has been split into multiple crates to make its code
  reusable. It is now possible for others to write their own key managers that
  use a different set of trusted policy signers.

- Add `oasis-node registry node is-registered` subcommand
  ([#2508](https://github.com/oasisprotocol/oasis-core/issues/2508))

  It checks whether the node is registered.

- Runtime node admission policies
  ([#2513](https://github.com/oasisprotocol/oasis-core/issues/2513))

  With this, each runtime can define its node admission policy.

  Currently only two policies should be supported:
  - Entity whitelist (only nodes belonging to whitelisted entities can register
    to host a runtime).
  - Anyone with enough stake (currently the only supported policy).

  The second one (anyone with enough stake) can introduce liveness issues as
  long as there is no slashing for compute node liveness (see
  [#2078](https://github.com/oasisprotocol/oasis-core/issues/2078)).

- go/keymanager: Support policy updates
  ([#2516](https://github.com/oasisprotocol/oasis-core/issues/2516))

  This change adds the ability for the key manager runtime owner to update
  the key manger policy document at runtime by submitting an appropriate
  transaction.

  Note: Depending on the nature of the update it may take additional epoch
  transitions for the key manager to be available to clients.

- Tooling for runtimes' node admission policy
  ([#2563](https://github.com/oasisprotocol/oasis-core/issues/2563))

  We added a policy type where you can whitelist the entities that can operate
  compute nodes.
  This adds the tooling around it so things like the registry runtime genesis
  init tool can set them up.

- Export signer public key to entity
  ([#2609](https://github.com/oasisprotocol/oasis-core/issues/2609))

  We added a command to export entities from existing signers, and a check to
  ensure that the entity and signer public keys match.

  This makes it so that a dummy entity cannot be used for signers backed by
  Ledger.

- go/registry: Handle the old and busted node descriptor envelope
  ([#2614](https://github.com/oasisprotocol/oasis-core/issues/2614))

  The old node descriptor envelope has one signature. The new envelope has
  multiple signatures, to ensure that the node has access to the private
  component of all public keys listed in the descriptor.

  The correct thing to do, from a security standpoint is to use a new set
  of genesis node descriptors. Instead, this change facilitates the transition
  in what is probably the worst possible way by:

  - Disabling signature verification entirely for node descriptors listed
    in the genesis document (Technically this can be avoided, but there
    are other changes to the node descriptor that require no verification
    to be done if backward compatibility is desired).

  - Providing a conversion tool that fixes up the envelopes to the new
    format.

  - Omitting descriptors that are obviously converted from state dumps.

  Note: Node descriptors that are using the now deprecated option to use
  the entity key for signing are not supported at all, and backward
  compatibility will NOT be maintained.

- go/oasis-node/cmd/debug/fixgenesis: Support migrating Node.Roles
  ([#2620](https://github.com/oasisprotocol/oasis-core/issues/2620))

  The `node.RolesMask` bit definitions have changed since the last major
  release deployed to the wild, so support migrating things by rewriting
  the node descriptor.

  Note: This assumes that signature validation in InitChain is disabled.

### Bug Fixes

- go/registry: deduplicate registry sanity checks and re-enable address checks
  ([#2428](https://github.com/oasisprotocol/oasis-core/issues/2428))

  Existing deployments had invalid P2P/Committee IDs and addresses as old code
  did not validate all the fields at node registration time. All ID and address
  validation checks are now enabled.

  Additionally, separate code paths were used for sanity checking of the genesis
  and for actual validation at registration time, which lead to some unexpected
  cases where invalid genesis documents were passing the validation. This code
  (at least for registry application) is now unified.

- Make oasis-node binaries made with GoReleaser via GitHub Actions reproducible
  again
  ([#2571](https://github.com/oasisprotocol/oasis-core/issues/2571))

  Add `-buildid=` back to `ldflags` to make builds reproducible again.

  As noted in
  [60641ce](https://github.com/oasisprotocol/oasis-core/commit/60641ce),
  this should be no longer necessary with Go 1.13.4+, but there appears to be a
  [specific issue with GoReleaser's build handling](
  https://github.com/oasislabs/goreleaser/issues/1).

- go/worker/storage: Fix sync deadlock
  ([#2584](https://github.com/oasisprotocol/oasis-core/issues/2584))

- go/consensus/tendermint: Always accept own transactions
  ([#2586](https://github.com/oasisprotocol/oasis-core/issues/2586))

  A validator node should always accept own transactions (signed by the node's
  identity key) regardless of the configured gas price.

- go/registry: Allow expired registrations at genesis
  ([#2598](https://github.com/oasisprotocol/oasis-core/issues/2598))

  The dump/restore process requires this to be permitted as expired
  registrations are persisted through an entity's debonding period.

- go/oasis-node/cmd/registry/runtime: Fix loading entities in registry runtime
  subcommands
  ([#2606](https://github.com/oasisprotocol/oasis-core/issues/2606))

- go/storage: Fix invalid memory access crash in Urkel tree
  ([#2611](https://github.com/oasisprotocol/oasis-core/issues/2611))

- go/consensus/tendermint/apps/staking: Fix epochtime overflow
  ([#2627](https://github.com/oasisprotocol/oasis-core/issues/2627))

- go/tendermint/keymanager: Error in Status() if keymanager doesn't exist
  ([#2628](https://github.com/oasisprotocol/oasis-core/issues/2628))

  This fixes panics in the key-manager client if keymanager for the specific
  runtime doesn't exist.

- go/oasis-node/cmd/stake: Make info subcommand tolerate invalid thresholds
  ([#2632](https://github.com/oasisprotocol/oasis-core/issues/2632))

  Change the subcommand to print valid staking threshold kinds and warn about
  invalid ones.

- go/staking/api: Check if thresholds for all kinds are defined in genesis
  ([#2633](https://github.com/oasisprotocol/oasis-core/issues/2633))

- go/cmd/registry/runtime: Fix provisioning a runtime without keymanager
  ([#2639](https://github.com/oasisprotocol/oasis-core/issues/2639))

- registry/api/sanitycheck: Move genesis stateroot check into registration
  ([#2643](https://github.com/oasisprotocol/oasis-core/issues/2643))

  Runtime genesis check should only be done when registering, not during the
  sanity checks.

- Make `oasis control is-synced` subcommand more verbose
  ([#2649](https://github.com/oasisprotocol/oasis-core/issues/2649))

  Running `oasis-node control is-synced` will now print a message indicating
  whether a node has completed initial syncing or not to stdout in addition to
  returning an appropriate status code.

### Internal changes

- go/genesis: Fix genesis tests and registry sanity checks
  ([#2589](https://github.com/oasisprotocol/oasis-core/issues/2589))

- github: Add ci-reproducibility workflow
  ([#2590](https://github.com/oasisprotocol/oasis-core/issues/2590))

  The workflow spawns two build jobs that use the same build environment, except
  for the path of the git checkout.
  The `oasis-node` binary is built two times, once directly via Make's
  `go build` invocation and the second time using the
  [GoReleaser](https://goreleaser.com/) tool that is used to make the official
  Oasis Core releases.
  The last workflow job compares both checksums of both builds and errors if
  they are not the same.

- go/consensus/tendermint/abci: Add mock ApplicationState
  ([#2629](https://github.com/oasisprotocol/oasis-core/issues/2629))

  This makes it easier to write unit tests for functions that require ABCI
  state.

## 20.2 (2020-01-21)

### Removals and Breaking changes

- go node: Unite compute, merge, and transaction scheduler roles
  ([#2107](https://github.com/oasisprotocol/oasis-core/issues/2107))

  We're removing the separation among registering nodes for the compute, merge,
  and transaction scheduler roles.
  You now have to register for and enable all or none of these roles, under a
  new, broadened, and confusing--you're welcome--term "compute".

- Simplify tendermint sentry node setup.
  ([#2362](https://github.com/oasisprotocol/oasis-core/issues/2362))

  Breaking configuration changes:
  - `worker.sentry.address` renamed to: `worker.registration.sentry.address`
  - `worker.sentry.cert_file` renamed to: `worker.registration.sentry.cert_file`
  - `tendermint.private_peer_id` removed
  - added `tendermint.sentry.upstream_address` which should be set on sentry
    node and it will set `tendermint.private_peer_id` and
    `tendermint.peristent_peer` for the configured addresses

- Charge gas for runtime transactions and suspend runtimes which do not pay
  periodic maintenance fees
  ([#2504](https://github.com/oasisprotocol/oasis-core/issues/2504))

  This introduces gas fees for submitting roothash commitments from runtime
  nodes. Since periodic maintenance work must be performed on each epoch
  transition (e.g., electing runtime committees), fees for that maintenance are
  paid by any nodes that register to perform work for a specific runtime. Fees
  are pre-paid for the number of epochs a node registers for.

  If the maintenance fees are not paid, the runtime gets suspended (so periodic
  work is not needed) and must be resumed by registering nodes.

- go: Rename compute -> executor
  ([#2525](https://github.com/oasisprotocol/oasis-core/issues/2525))

  It was proposed that we rename the "compute" phase (of the txnscheduler,
  _compute_, merge workflow) to "executor".

  Things that remain as "compute":
  - the registry node role
  - the registry runtime kind
  - the staking threshold kind
  - things actually referring to processing inputs to outputs
  - one of the drbg contexts

  So among things that are renamed are fields of the on-chain state and command
  line flags.

- `RuntimeID` is not hard-coded in the enclave anymore
  ([#2529](https://github.com/oasisprotocol/oasis-core/issues/2529))

  It is passed when dispatching the runtime. This enables the same runtime
  binary to be registered and executed multiple times with different
  `RuntimeID`.

### Features

- Consensus simulation mode and fee estimator
  ([#2521](https://github.com/oasisprotocol/oasis-core/issues/2521))

  This change allows the compute nodes to participate in networks which require
  gas fees for various operations in the network. Gas is automatically estimated
  by simulating transactions while gas price is currently "discovered" manually
  via node configuration.

  The following configuration flags are added:

  - `consensus.tendermint.submission.gas_price` should specify the gas price
    that the node will be using in all submitted transactions.
  - `consensus.tendermint.submission.max_fee` can optionally specify the maximum
    gas fee that the node will use in submitted transactions. If the computed
    fee would ever go over this limit, the transaction will not be submitted and
    an error will be returned instead.

- Optimize registry runtime lookups during node registration
  ([#2538](https://github.com/oasisprotocol/oasis-core/issues/2538))

  A performance optimization to avoid loading a list of all registered runtimes
  into memory in cases when only a specific runtime is actually needed.

### Bug Fixes

- Don't allow duplicate P2P connections from the same IP by default
  ([#2558](https://github.com/oasisprotocol/oasis-core/issues/2558))

- go/extra/stats: handle nil-votes and non-registered nodes
  ([#2566](https://github.com/oasisprotocol/oasis-core/issues/2566))

- go/oasis-node: Include account ID in `stake list -v` subcommand
  ([#2567](https://github.com/oasisprotocol/oasis-core/issues/2567))

  Changes `stake list -v` subcommand to return a map of IDs to accounts.

- Use a newer version of the oasis-core tendermint fork
  ([#2569](https://github.com/oasisprotocol/oasis-core/issues/2569))

  The updated fork has additional changes to tendermint to hopefully
  prevent the node from crashing if the file descriptors available to the
  process get exhausted due to hitting the rlimit.

  While no forward progress can be made while the node is re-opening the
  WAL, the node will now flush incoming connections that are in the process
  of handshaking, and retry re-opening the WAL instead of crashing with
  a panic.

### Documentation improvements

- Document versioning scheme used for Oasis Core and its Protocols
  ([#2457](https://github.com/oasisprotocol/oasis-core/issues/2457))

  See [Versioning Scheme](./docs/versioning.md).

- Document Oasis Core's release process
  ([#2565](https://github.com/oasisprotocol/oasis-core/issues/2565))

  See [Release process](./docs/release-process.md).

## 20.1 (2020-01-14)

### Features

- go/worker/txnscheduler: Check transactions before queuing them
  ([#2502](https://github.com/oasisprotocol/oasis-core/issues/2502))

  The transaction scheduler can now optionally run runtimes and
  check transactions before scheduling them (see issue #1963).
  This functionality is disabled by default, enable it with
  `worker.txn_scheduler.check_tx.enabled`.

### Bug Fixes

- go/runtime/client: Return empty sequences instead of nil
  ([#2542](https://github.com/oasisprotocol/oasis-core/issues/2542))

  The runtime client endpoint should return empty sequences instead of `nil` as
  serde doesn't know how to decode a `NULL` when the expected type is a
  sequence.

- Temporarily disable consensus address checks at genesis
  ([#2552](https://github.com/oasisprotocol/oasis-core/issues/2552))

## 20.0 (2020-01-10)

### Removals and Breaking changes

- Use the new runtime ID allocation scheme
  ([#1693](https://github.com/oasisprotocol/oasis-core/issues/1693))

  This change alters the runtime ID allocation scheme to reserve the first
  64 bits for flags indicating various properties of the runtime, and to
  forbid registering runtimes that have test runtime IDs unless the
  appropriate consensus flag is set.

- Remove staking-related roothash messages
  ([#2377](https://github.com/oasisprotocol/oasis-core/issues/2377))

  There is no longer a plan to support direct manipulation of the staking
  accounts from the runtimes in order to isolate the runtimes from corrupting
  the consensus layer.

  To reduce complexity, the staking-related roothash messages were removed. The
  general roothash message mechanism stayed as-is since it may be useful in the
  future, but any commits with non-empty messages are rejected for now.

- Refactoring of roothash genesis block for runtime
  ([#2426](https://github.com/oasisprotocol/oasis-core/issues/2426))

  - `RuntimeGenesis.Round` field was added to the roothash block for the runtime
    which can be set by `--runtime.genesis.round` flag.
  - The `RuntimeGenesis.StorageReceipt` field was replaced by `StorageReceipts`
    list, one for each storage node.
  - Support for `base64` encoding/decoding of `Bytes` was added in rust.

- When registering a new runtime, require that the given key manager ID points
  to a valid key manager in the registry
  ([#2459](https://github.com/oasisprotocol/oasis-core/issues/2459))

- Remove `oasis-node debug dummy` sub-commands
  ([#2492](https://github.com/oasisprotocol/oasis-core/issues/2492))

  These are only useful for testing, and our test harness has a internal Go API
  that removes the need to have this functionality exposed as a sub-command.

- Make storage per-runtime
  ([#2494](https://github.com/oasisprotocol/oasis-core/issues/2494))

  Previously there was a single storage backend used by `oasis-node` which
  required that a single database supported multiple namespaces for the case
  when multiple runtimes were being used in a single node.

  This change simplifies the storage database backends by removing the need for
  backends to implement multi-namespace support, reducing overhead and cleanly
  separating per-runtime state.

  Due to this changing the internal database format, this breaks previous
  (compute node) deployments with no way to do an automatic migration.

### Features

- Add `oasis-node debug storage export` sub-command
  ([#1845](https://github.com/oasisprotocol/oasis-core/issues/1845))

- Add fuzzing for consensus methods
  ([#2245](https://github.com/oasisprotocol/oasis-core/issues/2245))

  Initial support for fuzzing was added, along with an implementation of
  it for some of the consensus methods. The implementation uses
  oasis-core's demultiplexing and method dispatch mechanisms.

- Add storage backend fuzzing
  ([#2246](https://github.com/oasisprotocol/oasis-core/issues/2246))

  Based on the work done for consensus fuzzing, support was added to run fuzzing
  jobs on the storage api backend.

- Add `oasis-node unsafe-reset` sub-command which resets the node back to a
  freshly provisioned state, preserving any key material if it exists
  ([#2435](https://github.com/oasisprotocol/oasis-core/issues/2435))

- Add txsource
  ([#2478](https://github.com/oasisprotocol/oasis-core/issues/2478))

  The so-called "txsource" utility introduced in this PR is a starting point for
  something like a client that sends transactions for a long period of time, for
  the purpose of creating long-running tests.

  With this change is a preliminary sample "workload"--a DRBG-backed schedule of
  transactions--which transfers staking tokens around among a set of test
  accounts.

- Add consensus block and transaction metadata accessors
  ([#2482](https://github.com/oasisprotocol/oasis-core/issues/2482))

  In order to enable people to build "network explorers", we exposed some
  additional methods via the consensus API endpoint, specifically:

  - Consensus block metadata.
  - Access to raw consensus transactions within a block.
  - Stream of consensus blocks as they are finalized.

- Make maximum in-memory cache size for runtime storage configurable
  ([#2494](https://github.com/oasisprotocol/oasis-core/issues/2494))

  Previously the value of 64mb was always used as the size of the in-memory
  storage cache. This adds a new configuration parameter/command-line flag
  `--storage.max_cache_size` which configures the maximum size of the in-memory
  runtime storage cache.

- Undisable transfers for some senders
  ([#2498](https://github.com/oasisprotocol/oasis-core/issues/2498))

  Ostensibly for faucet purposes while we run the rest of the network with
  transfers disabled, this lets us identify a whitelist of accounts from which
  we allow transfers when otherwise transfers are disabled.

  Configure this with a map of allowed senders' public keys -> `true` in the
  new `undisable_transfers_from` field in the staking consensus parameters
  object along with `"disable_transfers": true`.

- Entity block signatures count tool
  ([#2500](https://github.com/oasisprotocol/oasis-core/issues/2500))

  The tool uses node consensus and registry API endpoints and computes the per
  entity block signature counts.

### Bug Fixes

- Reduce Badger in-memory cache sizes
  ([#2484](https://github.com/oasisprotocol/oasis-core/issues/2484))

  The default is 1 GiB per badger instance and we use a few instances so this
  resulted in some nice memory usage.

## 19.0 (2019-12-18)

### Process

- Start using the new Versioning and Release process for Oasis Core.
  ([#2419](https://github.com/oasisprotocol/oasis-core/issues/2419))

  Adopt a [CalVer](http://calver.org) (calendar versioning) scheme for Oasis
  Core (as a whole) with the following format:

  ```text
  YY.MINOR[.MICRO][-MODIFIER]
  ```

  where:
  - `YY` represents short year (e.g. 19, 20, 21, ...),
  - `MINOR` represents the minor version starting with zero (e.g. 0, 1, 2, 3,
    ...),
  - `MICRO` represents (optional) final number in the version (sometimes
    referred to as the "patch" segment) (e.g. 0, 1, 2, 3, ...).

    If the `MICRO` version is 0, it is be omitted.
  - `MODIFIER` represents (optional) build metadata, e.g. `git8c01382`.

  The new Versioning and Release process will be described in more detail in
  the future. For more details, see [#2457](
  https://github.com/oasisprotocol/oasis-core/issues/2457).
