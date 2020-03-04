# Change Log

All notables changes to this project are documented in this file.

The format is inspired by [Keep a Changelog].

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/

<!-- markdownlint-disable no-duplicate-heading -->

<!-- NOTE: towncrier will not alter content above the TOWNCRIER line below. -->

<!-- TOWNCRIER -->

## 20.4 (2020-03-04)

### Removals and Breaking changes

- go/registry: Enable non-genesis runtime registrations by default
  ([#2406](https://github.com/oasislabs/oasis-core/issues/2406))

- Optionally require a deposit for registering a runtime
  ([#2638](https://github.com/oasislabs/oasis-core/issues/2638))

- go/staking: Add stateful stake accumulator
  ([#2642](https://github.com/oasislabs/oasis-core/issues/2642))

  Previously there was no central place to account for all the parts that need
  to claim some part of an entity's stake which required approximations all
  around.

  This is now changed and a stateful stake accumulator is added to each escrow
  account. The stake accumulator is used to track stake claims from different
  apps (currently only the registry).

  This change also means that node registration will now always require the
  correct amount of stake.

- go/registry: Add explicit EntityID field to Runtime descriptors
  ([#2642](https://github.com/oasislabs/oasis-core/issues/2642))

- go/staking: More reward for more signatures
  ([#2647](https://github.com/oasislabs/oasis-core/issues/2647))

  We're adjusting fee distribution and the block proposing staking reward to
  incentivize proposers to create blocks with more signatures.

- Send and check expected epoch number during transaction execution
  ([#2650](https://github.com/oasislabs/oasis-core/issues/2650))

  Stress tests revealed some race conditions during transaction execution when
  there is an epoch transition. Runtime client now sends `expectedEpochNumber`
  parameter in `SubmitTx` call. The transaction scheduler checks whether the
  expected epoch matches its local one. Additionally, if state transition occurs
  during transaction execution, Executor and Merge committee correctly abort the
  transaction.

- go/staking: Add per-account lockup
  ([#2672](https://github.com/oasislabs/oasis-core/issues/2672))

  With this, we'll be able to set up special accounts in the genesis
  document where they're not permitted to transfer staking tokens until
  a the specified epoch time.
  They can still delegate during that time.

- Use `--stake.shares` flag when specifying shares to reclaim from an escrow
  ([#2690](https://github.com/oasislabs/oasis-core/issues/2690))

  Previously, the `oasis-node stake account gen_reclaim_escrow` subcommand
  erroneously used the `--stake.amount` flag for specifying the amount of shares
  to reclaim from an escrow.

### Features

- Implement node upgrade mechanism
  ([#2607](https://github.com/oasislabs/oasis-core/issues/2607))

  The node now accepts upgrade descriptors which describe the upgrade to carry
  out.

  The node can shut down at the appropriate epoch and then execute any required
  migration handlers on the node itself and on the consensus layer.

  Once a descriptor is submitted, the old node can be normally restarted and
  used until the upgrade epoch is reached; the new binary can not be used at
  all until the old binary has had a chance to reach the upgrade epoch.
  Once that is reached, the old binary will refuse to start.

- go/common/crypto/signature/signers/remote: Add experimental remote signer
  ([#2686](https://github.com/oasislabs/oasis-core/issues/2686))

  This adds an experimental remote signer, reference remote signer
  implementation, and theoretically allows the node to be ran with a
  non-file based signer backend.

- go/extra/stats: Figure out how many blocks entities propose
  ([#2693](https://github.com/oasislabs/oasis-core/issues/2693))

  Cross reference which node proposed each block and report these
  per-entity as well.

- go/extra/stats: Availability ranking for next Quest phase
  ([#2699](https://github.com/oasislabs/oasis-core/issues/2699))

  A new availability score will take into account more than the number of
  block signatures alone.

  This introduces the mechanism to compute a score and print the
  rankings based on that.
  This also implements a provisional scoring formula.

- go/oasis-node/txsource: Add registration workload
  ([#2718](https://github.com/oasislabs/oasis-core/issues/2718))

- go/oasis-node/txsource: Add parallel workload
  ([#2724](https://github.com/oasislabs/oasis-core/issues/2724))

- go/scheduler: Validators now returns validators by node ID
  ([#2739](https://github.com/oasislabs/oasis-core/issues/2739))

  The consensus ID isn't all that useful for most external callers, so
  querying it should just return the validators by node ID instead.

- go/staking: Add a `Delegations()` call, and expose it over gRPC
  ([#2740](https://github.com/oasislabs/oasis-core/issues/2740))

  This adds a `Delegations()` call in the spirit of `DebondingDelegations()`
  that returns a map of delegations for a given delegator.

- go/oasis-node/txsource: Use a special account for funding accounts
  ([#2744](https://github.com/oasislabs/oasis-core/issues/2744))

  Generate and fund a special account that is used for funding accounts during
  the workload instead of hard-coding funding for fixed addresses.

  Additionally, start using fees and non-zero gas prices in workloads.

### Bug Fixes

- go/storage/client: Retry storage ops on specific errors
  ([#1865](https://github.com/oasislabs/oasis-core/issues/1865))

- go/tendermint: Unfatalize seed populating nodes from genesis
  ([#2554](https://github.com/oasislabs/oasis-core/issues/2554))

  In some cases we'd prefer to include some nodes in the genesis document
  even when they're registered with an invalid address.

  This makes the seed node ignore those entries and carry on, while
  keeping those entries available for the rest of the system.

- go: Re-enable signature verification disabled for migration
  ([#2615](https://github.com/oasislabs/oasis-core/issues/2615))

  Now that the migration has hopefully been done, re-enable all of the
  signature verification that was disabled for the sake of allowing for
  migration.

- go: Don't scan the whole keyspace in badger's tendermint DB implementation
  ([#2664](https://github.com/oasislabs/oasis-core/issues/2664))

  When we run off the end of a range iteration.

- runtime: Bump ring to 0.16.11, snow to 0.6.2, Rust to 2020-02-16
  ([#2666](https://github.com/oasislabs/oasis-core/issues/2666))

- go/staking/api: Fix genesis sanity check for nonexisting accounts
  ([#2671](https://github.com/oasislabs/oasis-core/issues/2671))

  Detect when a (debonding) delegation is specified for a nonexisting account
  and report an appropriate error.

- go/storage/mkvs: Fix iterator bug
  ([#2691](https://github.com/oasislabs/oasis-core/issues/2691))

- go/storage/mkvs: Fix bug in `key.Merge` operation with extra bytes
  ([#2698](https://github.com/oasislabs/oasis-core/issues/2698))

- go/storage/mkvs: Fix removal crash when key is too short
  ([#2698](https://github.com/oasislabs/oasis-core/issues/2698))

- go/storage/mkvs: Fix node unmarshallers
  ([#2703](https://github.com/oasislabs/oasis-core/issues/2703))

- go/storage/mkvs: Fix proof verifier
  ([#2703](https://github.com/oasislabs/oasis-core/issues/2703))

- go/consensus/tendermint: Properly cache consensus parameters
  ([#2708](https://github.com/oasislabs/oasis-core/issues/2708))

- go/badger: Enable truncate to recover from corrupted value log file
  ([#2732](https://github.com/oasislabs/oasis-core/issues/2732))

  Apparently badger is not at all resilient to crashes unless the truncate
  option is enabled.

- go/oasis-net-runner/fixtures: Increase scheduler max batch size to 16 MiB
  ([#2741](https://github.com/oasislabs/oasis-core/issues/2741))

  This change facilitates RPCs to larger, more featureful runtimes.

- go/common/version: Allow omission of trailing numbers in `parSemVerStr()`
  ([#2742](https://github.com/oasislabs/oasis-core/issues/2742))

  Go's [`runtime.Version()`](https://golang.org/pkg/runtime/#Version) function
  can omit the patch number, so augment `parSemVerStr()` to handle that.

### Internal changes

- github: Bump GoReleaser to 0.127.0 and switch back to upstream
  ([#2564](https://github.com/oasislabs/oasis-core/issues/2564))

- github: Add new steps to ci-lint workflow
  ([#2572](https://github.com/oasislabs/oasis-core/issues/2572),
   [#2692](https://github.com/oasislabs/oasis-core/issues/2692),
   [#2717](https://github.com/oasislabs/oasis-core/issues/2717))

  Add _Lint git commits_, _Lint Markdown files_, _Lint Change Log fragments_ and
  _Check go mod tidy_ steps to ci-lint GitHub Actions workflow.

  Remove _Lint Git commits_ step from Buildkite's CI pipeline.

- ci: Skip some steps for non-code changes
  ([#2573](https://github.com/oasislabs/oasis-core/issues/2573),
   [#2702](https://github.com/oasislabs/oasis-core/issues/2702))

  When one makes a pull request that e.g. only adds documentation or
  assembles the Change Log from fragments, all the *heavy* Buildkite
  pipeline steps (e.g. Go/Rust building, Go tests, E2E tests) should be
  skipped.

- go/common/cbor: Bump fxamacker/cbor to v2.2
  ([#2635](https://github.com/oasislabs/oasis-core/issues/2635))

- go/storage/mkvs: Fuzz storage proof decoder
  ([#2637](https://github.com/oasislabs/oasis-core/issues/2637))

- ci: merge coverage files per job
  ([#2644](https://github.com/oasislabs/oasis-core/issues/2644))

- go/oasis-test-runner: Update multiple-runtimes E2E test
  ([#2650](https://github.com/oasislabs/oasis-core/issues/2650))

  Reduce all group sizes to 1 with no backups, use `EpochtimeMock` to avoid
  unexpected blocks, add `numComputeWorkers` parameter.

- Replace redundant fields with `Consensus` accessors
  ([#2650](https://github.com/oasislabs/oasis-core/issues/2650))

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
  ([#2659](https://github.com/oasislabs/oasis-core/issues/2659))

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
  ([#2662](https://github.com/oasislabs/oasis-core/issues/2662))

  For more details, see the description in [Change Log fragments](
  .changelog/README.md).

- Make: Add lint targets
  ([#2662](https://github.com/oasislabs/oasis-core/issues/2662),
   [#2692](https://github.com/oasislabs/oasis-core/issues/2692))

  Add a general `lint` target that depends on the following lint targets:

  - `lint-go`: Lint Go code,
  - `lint-git`: Lint git commits,
  - `lint-md`: Lint Markdown files (except Change Log fragments),
  - `lint-changelog`: Lint Change Log fragments.

- Add sanity checks for stake accumulator state integrity
  ([#2665](https://github.com/oasislabs/oasis-core/issues/2665))

- go/consensus/tendermint: Don't use `UnsafeSigner`
  ([#2670](https://github.com/oasislabs/oasis-core/issues/2670))

- rust: Update ed25519-dalek and associated dependencies
  ([#2678](https://github.com/oasislabs/oasis-core/issues/2678))

  This change updates ed25519-dalek, rand and x25519-dalek.

- Bump minimum Go version to 1.13.8
  ([#2689](https://github.com/oasislabs/oasis-core/issues/2689))

- go/storage/mkvs: Add overlay tree to support rolling back state
  ([#2691](https://github.com/oasislabs/oasis-core/issues/2691))

- go/storage/mkvs: Make `Tree` an interface
  ([#2691](https://github.com/oasislabs/oasis-core/issues/2691))

- gitlint: Require body length of at least 20 characters (if body exists)
  ([#2692](https://github.com/oasislabs/oasis-core/issues/2692))

- Make build-fuzz work again, test it on CI
  ([#2695](https://github.com/oasislabs/oasis-core/issues/2695))

- changelog: Reference multiple issues/pull requests for a single entry
  ([#2697](https://github.com/oasislabs/oasis-core/issues/2697))

  For more details, see the description in [Change Log fragments](
  .changelog/README.md#multiple-issues--pull-requests-for-a-single-fragment).

- go/storage/mkvs: Add MKVS fuzzing
  ([#2698](https://github.com/oasislabs/oasis-core/issues/2698))

- github: Don't trigger ci-reproducibility workflow for pull requests
  ([#2704](https://github.com/oasislabs/oasis-core/issues/2704))

- go/oasis-test-runner: Improve txsource E2E test
  ([#2709](https://github.com/oasislabs/oasis-core/issues/2709))

  This adds the following general txsource scenario features:

  - Support for multiple parallel workloads.
  - Restart random nodes on specified interval.
  - Ensure consensus liveness for the duration of the test.

  It also adds an oversized txsource workload which submits oversized
  transactions periodically.

- go/consensus/tendermint: Expire txes when CheckTx is disabled
  ([#2720](https://github.com/oasislabs/oasis-core/issues/2720))

  When CheckTx is disabled (for debug purposes only, e.g. in E2E tests), we
  still need to periodically remove old transactions as otherwise the mempool
  will fill up. Keep track of transactions were added and invalidate them when
  they expire.

- runtime: Remove the non-webpki/snow related uses of ring
  ([#2733](https://github.com/oasislabs/oasis-core/issues/2733))

  As much as I like the concept of ring as a library, and the
  implementation, the SGX support situation is ridiculous, and we should
  minimize the use of the library for cases where alternatives exist.

## 20.3 (2020-02-06)

### Removals and Breaking changes

- Add gRPC Sentry Nodes support
  ([#1829](https://github.com/oasislabs/oasis-core/issues/1829))

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
  ([#2058](https://github.com/oasislabs/oasis-core/issues/2058))

  This change is breaking as the old certificates are no longer supported,
  and they must be regenerated.  Note that this uses the slower runtime
  library ed25519 implementation instead of ours due to runtime library
  limitations.

- All marshalable enumerations in the code were checked and the default
  `Invalid = 0` value was added, if it didn't exist before
  ([#2546](https://github.com/oasislabs/oasis-core/issues/2546))

  This makes the code less error prone and more secure, because it requires
  the enum field to be explicitly set, if some meaningful behavior is expected
  from the corresponding object.

- go/registry: Add `ConsensusParams.MaxNodeExpiration`
  ([#2580](https://github.com/oasislabs/oasis-core/issues/2580))

  Node expirations being unbound is likely a bad idea.  This adds a
  consensus parameter that limits the maximum lifespan of a node
  registration, to a pre-defined number of epochs (default 5).

  Additionally the genesis document sanity checker is now capable of
  detecting if genesis node descriptors have invalid expirations.

  Note: Existing deployments will need to alter the state dump to
  configure the maximum node expiration manually before a restore
  will succeed.

- go/common/crypto/signature: Use base64-encoded IDs/public keys
  ([#2588](https://github.com/oasislabs/oasis-core/issues/2588))

  Change `String()` method to return base64-encoded representation of a public
  key instead of the hex-encoded representation to unify CLI experience when
  passing/printing IDs/public keys.

- go/registry: Disallow entity signed node registrations
  ([#2594](https://github.com/oasislabs/oasis-core/issues/2594))

  This feature is mostly useful for testing and should not be used in
  production, basically ever.  Additionally, when provisioning node
  descriptors, `--node.is_self_signed` is now the default.

  Note: Breaking if anyone happens to use said feature, but enabling said
  feature is already feature-gated, so this is unlikely.

- go/registry: Ensure that node descriptors are signed by all public keys
  ([#2599](https://github.com/oasislabs/oasis-core/issues/2599))

  To ensure that nodes demonstrate proof that they posses the private keys
  for all public keys contained in their descriptor, node descriptors now
  must be signed by the node, consensus, p2p and TLS certificate key.

  Note: Node descriptors generated prior to this change are now invalid and
  will be rejected.

- Rewards and fees consensus parameters
  ([#2624](https://github.com/oasislabs/oasis-core/issues/2624))

  Previously things like reward "factors" and fee distribution "weights" were
  hardcoded. But we have pretty good support for managing consensus parameters,
  so we ought to move them there.

- Special rewards for block proposer
  ([#2625](https://github.com/oasislabs/oasis-core/issues/2625))

  - a larger portion of the fees
  - an additional reward

- go/consensus/tendermint: mux offset block height consistently
  ([#2634](https://github.com/oasislabs/oasis-core/issues/2634))

  We've been using `blockHeight+1` for getting the epoch time except for on
  blockHeight=1.
  The hypothesis in this change is that we don't need that special case.

- Tendermint P2P configuration parameters
  ([#2646](https://github.com/oasislabs/oasis-core/issues/2646))

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
  ([#2649](https://github.com/oasislabs/oasis-core/issues/2649))

  The `show-node-address` subcommmand returns node's public key converted to
  Tendermint's address format.
  It replaces the `oasis-node debug tendermint show-node-id` subcommand.

  The `show-consensus-address` subcommand returns node's consensus key converted
  to Tendermint's address format.

### Features

- Refresh node descriptors mid-epoch
  ([#1794](https://github.com/oasislabs/oasis-core/issues/1794))

  Previously node descriptors were only refreshed on an epoch transition which
  meant that any later updates were ignored until the next epoch.
  This caused stale RAKs to stay in effect when runtime restarts happened,
  causing attestation verification to fail.

  Enabling mid-epoch refresh makes nodes stay up to date with committee member
  node descriptor updates.

- go/worker/storage: Add configurable limits for storage operations
  ([#1914](https://github.com/oasislabs/oasis-core/issues/1914))

- Flexible key manager policy signers
  ([#2444](https://github.com/oasislabs/oasis-core/issues/2444))

  The key manager runtime has been split into multiple crates to make its code
  reusable. It is now possible for others to write their own key managers that
  use a different set of trusted policy signers.

- Add `oasis-node registry node is-registered` subcommand
  ([#2508](https://github.com/oasislabs/oasis-core/issues/2508))

  It checks whether the node is registered.

- Runtime node admission policies
  ([#2513](https://github.com/oasislabs/oasis-core/issues/2513))

  With this, each runtime can define its node admission policy.

  Currently only two policies should be supported:
  - Entity whitelist (only nodes belonging to whitelisted entities can register
    to host a runtime).
  - Anyone with enough stake (currently the only supported policy).

  The second one (anyone with enough stake) can introduce liveness issues as
  long as there is no slashing for compute node liveness (see
  [#2078](https://github.com/oasislabs/oasis-core/issues/2078)).

- go/keymanager: Support policy updates
  ([#2516](https://github.com/oasislabs/oasis-core/issues/2516))

  This change adds the ability for the key manager runtime owner to update
  the key manger policy document at runtime by submitting an appropriate
  transaction.

  Note: Depending on the nature of the update it may take additional epoch
  transitions for the key manager to be available to clients.

- Tooling for runtimes' node admission policy
  ([#2563](https://github.com/oasislabs/oasis-core/issues/2563))

  We added a policy type where you can whitelist the entities that can operate
  compute nodes.
  This adds the tooling around it so things like the registry runtime genesis
  init tool can set them up.

- Export signer public key to entity
  ([#2609](https://github.com/oasislabs/oasis-core/issues/2609))

  We added a command to export entities from existing signers, and a check to
  ensure that the entity and signer public keys match.

  This makes it so that a dummy entity cannot be used for signers backed by
  Ledger.

- go/registry: Handle the old and busted node descriptor envelope
  ([#2614](https://github.com/oasislabs/oasis-core/issues/2614))

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
  ([#2620](https://github.com/oasislabs/oasis-core/issues/2620))

  The `node.RolesMask` bit definitions have changed since the last major
  release deployed to the wild, so support migrating things by rewriting
  the node descriptor.

  Note: This assumes that signature validation in InitChain is disabled.

### Bug Fixes

- go/registry: deduplicate registry sanity checks and re-enable address checks
  ([#2428](https://github.com/oasislabs/oasis-core/issues/2428))

  Existing deployments had invalid P2P/Committee IDs and addresses as old code
  did not validate all the fields at node registration time. All ID and address
  validation checks are now enabled.

  Additionally, separate code paths were used for sanity checking of the genesis
  and for actual validation at registration time, which lead to some unexpected
  cases where invalid genesis documents were passing the validation. This code
  (at least for registry application) is now unified.

- Make oasis-node binaries made with GoReleaser via GitHub Actions reproducible
  again
  ([#2571](https://github.com/oasislabs/oasis-core/issues/2571))

  Add `-buildid=` back to `ldflags` to make builds reproducible again.

  As noted in [60641ce](https://github.com/oasislabs/oasis-core/commit/60641ce),
  this should be no longer necessary with Go 1.13.4+, but there appears to be a
  [specific issue with GoReleaser's build handling](
  https://github.com/oasislabs/goreleaser/issues/1).

- go/worker/storage: Fix sync deadlock
  ([#2584](https://github.com/oasislabs/oasis-core/issues/2584))

- go/consensus/tendermint: Always accept own transactions
  ([#2586](https://github.com/oasislabs/oasis-core/issues/2586))

  A validator node should always accept own transactions (signed by the node's
  identity key) regardless of the configured gas price.

- go/registry: Allow expired registrations at genesis
  ([#2598](https://github.com/oasislabs/oasis-core/issues/2598))

  The dump/restore process requires this to be permitted as expired
  registrations are persisted through an entity's debonding period.

- go/oasis-node/cmd/registry/runtime: Fix loading entities in registry runtime
  subcommands
  ([#2606](https://github.com/oasislabs/oasis-core/issues/2606))

- go/storage: Fix invalid memory access crash in Urkel tree
  ([#2611](https://github.com/oasislabs/oasis-core/issues/2611))

- go/consensus/tendermint/apps/staking: Fix epochtime overflow
  ([#2627](https://github.com/oasislabs/oasis-core/issues/2627))

- go/tendermint/keymanager: Error in Status() if keymanager doesn't exist
  ([#2628](https://github.com/oasislabs/oasis-core/issues/2628))

  This fixes panics in the key-manager client if keymanager for the specific
  runtime doesn't exist.

- go/oasis-node/cmd/stake: Make info subcommand tolerate invalid thresholds
  ([#2632](https://github.com/oasislabs/oasis-core/issues/2632))

  Change the subcommand to print valid staking threshold kinds and warn about
  invalid ones.

- go/staking/api: Check if thresholds for all kinds are defined in genesis
  ([#2633](https://github.com/oasislabs/oasis-core/issues/2633))

- go/cmd/registry/runtime: Fix provisioning a runtime without keymanager
  ([#2639](https://github.com/oasislabs/oasis-core/issues/2639))

- registry/api/sanitycheck: Move genesis stateroot check into registration
  ([#2643](https://github.com/oasislabs/oasis-core/issues/2643))

  Runtime genesis check should only be done when registering, not during the
  sanity checks.

- Make `oasis control is-synced` subcommand more verbose
  ([#2649](https://github.com/oasislabs/oasis-core/issues/2649))

  Running `oasis-node control is-synced` will now print a message indicating
  whether a node has completed initial syncing or not to stdout in addition to
  returning an appropriate status code.

### Internal changes

- go/genesis: Fix genesis tests and registry sanity checks
  ([#2589](https://github.com/oasislabs/oasis-core/issues/2589))

- github: Add ci-reproducibility workflow
  ([#2590](https://github.com/oasislabs/oasis-core/issues/2590))

  The workflow spawns two build jobs that use the same build environment, except
  for the path of the git checkout.
  The `oasis-node` binary is built two times, once directly via Make's
  `go build` invocation and the second time using the
  [GoReleaser](https://goreleaser.com/) tool that is used to make the official
  Oasis Core releases.
  The last workflow job compares both checksums of both builds and errors if
  they are not the same.

- go/consensus/tendermint/abci: Add mock ApplicationState
  ([#2629](https://github.com/oasislabs/oasis-core/issues/2629))

  This makes it easier to write unit tests for functions that require ABCI
  state.

## 20.2 (2020-01-21)

### Removals and Breaking changes

- go node: Unite compute, merge, and transaction scheduler roles
  ([#2107](https://github.com/oasislabs/oasis-core/issues/2107))

  We're removing the separation among registering nodes for the compute, merge,
  and transaction scheduler roles.
  You now have to register for and enable all or none of these roles, under a
  new, broadened, and confusing--you're welcome--term "compute".

- Simplify tendermint sentry node setup.
  ([#2362](https://github.com/oasislabs/oasis-core/issues/2362))

  Breaking configuration changes:
  - `worker.sentry.address` renamed to: `worker.registration.sentry.address`
  - `worker.sentry.cert_file` renamed to: `worker.registration.sentry.cert_file`
  - `tendermint.private_peer_id` removed
  - added `tendermint.sentry.upstream_address` which should be set on sentry
    node and it will set `tendermint.private_peer_id` and
    `tendermint.peristent_peer` for the configured addresses

- Charge gas for runtime transactions and suspend runtimes which do not pay
  periodic maintenance fees
  ([#2504](https://github.com/oasislabs/oasis-core/issues/2504))

  This introduces gas fees for submitting roothash commitments from runtime
  nodes. Since periodic maintenance work must be performed on each epoch
  transition (e.g., electing runtime committees), fees for that maintenance are
  paid by any nodes that register to perform work for a specific runtime. Fees
  are pre-paid for the number of epochs a node registers for.

  If the maintenance fees are not paid, the runtime gets suspended (so periodic
  work is not needed) and must be resumed by registering nodes.

- go: Rename compute -> executor
  ([#2525](https://github.com/oasislabs/oasis-core/issues/2525))

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
  ([#2529](https://github.com/oasislabs/oasis-core/issues/2529))

  It is passed when dispatching the runtime. This enables the same runtime
  binary to be registered and executed multiple times with different
  `RuntimeID`.

### Features

- Consensus simulation mode and fee estimator
  ([#2521](https://github.com/oasislabs/oasis-core/issues/2521))

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
  ([#2538](https://github.com/oasislabs/oasis-core/issues/2538))

  A performance optimization to avoid loading a list of all registered runtimes
  into memory in cases when only a specific runtime is actually needed.

### Bug Fixes

- Don't allow duplicate P2P connections from the same IP by default
  ([#2558](https://github.com/oasislabs/oasis-core/issues/2558))

- go/extra/stats: handle nil-votes and non-registered nodes
  ([#2566](https://github.com/oasislabs/oasis-core/issues/2566))

- go/oasis-node: Include account ID in `stake list -v` subcommand
  ([#2567](https://github.com/oasislabs/oasis-core/issues/2567))

  Changes `stake list -v` subcommand to return a map of IDs to accounts.

- Use a newer version of the oasis-core tendermint fork
  ([#2569](https://github.com/oasislabs/oasis-core/issues/2569))

  The updated fork has additional changes to tendermint to hopefully
  prevent the node from crashing if the file descriptors available to the
  process get exhausted due to hitting the rlimit.

  While no forward progress can be made while the node is re-opening the
  WAL, the node will now flush incoming connections that are in the process
  of handshaking, and retry re-opening the WAL instead of crashing with
  a panic.

### Documentation improvements

- Document versioning scheme used for Oasis Core and its Protocols
  ([#2457](https://github.com/oasislabs/oasis-core/issues/2457))

  See [Versioning Scheme](./docs/versioning.md).

- Document Oasis Core's release process
  ([#2565](https://github.com/oasislabs/oasis-core/issues/2565))

  See [Release process](./docs/release-process.md).

## 20.1 (2020-01-14)

### Features

- go/worker/txnscheduler: Check transactions before queuing them
  ([#2502](https://github.com/oasislabs/oasis-core/issues/2502))

  The transaction scheduler can now optionally run runtimes and
  check transactions before scheduling them (see issue #1963).
  This functionality is disabled by default, enable it with
  `worker.txn_scheduler.check_tx.enabled`.

### Bug Fixes

- go/runtime/client: Return empty sequences instead of nil
  ([#2542](https://github.com/oasislabs/oasis-core/issues/2542))

  The runtime client endpoint should return empty sequences instead of `nil` as
  serde doesn't know how to decode a `NULL` when the expected type is a
  sequence.

- Temporarily disable consensus address checks at genesis
  ([#2552](https://github.com/oasislabs/oasis-core/issues/2552))

## 20.0 (2020-01-10)

### Removals and Breaking changes

- Use the new runtime ID allocation scheme
  ([#1693](https://github.com/oasislabs/oasis-core/issues/1693))

  This change alters the runtime ID allocation scheme to reserve the first
  64 bits for flags indicating various properties of the runtime, and to
  forbid registering runtimes that have test runtime IDs unless the
  appropriate consensus flag is set.

- Remove staking-related roothash messages
  ([#2377](https://github.com/oasislabs/oasis-core/issues/2377))

  There is no longer a plan to support direct manipulation of the staking
  accounts from the runtimes in order to isolate the runtimes from corrupting
  the consensus layer.

  To reduce complexity, the staking-related roothash messages were removed. The
  general roothash message mechanism stayed as-is since it may be useful in the
  future, but any commits with non-empty messages are rejected for now.

- Refactoring of roothash genesis block for runtime
  ([#2426](https://github.com/oasislabs/oasis-core/issues/2426))

  - `RuntimeGenesis.Round` field was added to the roothash block for the runtime
    which can be set by `--runtime.genesis.round` flag.
  - The `RuntimeGenesis.StorageReceipt` field was replaced by `StorageReceipts`
    list, one for each storage node.
  - Support for `base64` encoding/decoding of `Bytes` was added in rust.

- When registering a new runtime, require that the given key manager ID points
  to a valid key manager in the registry
  ([#2459](https://github.com/oasislabs/oasis-core/issues/2459))

- Remove `oasis-node debug dummy` sub-commands
  ([#2492](https://github.com/oasislabs/oasis-core/issues/2492))

  These are only useful for testing, and our test harness has a internal Go API
  that removes the need to have this functionality exposed as a sub-command.

- Make storage per-runtime
  ([#2494](https://github.com/oasislabs/oasis-core/issues/2494))

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
  ([#1845](https://github.com/oasislabs/oasis-core/issues/1845))

- Add fuzzing for consensus methods
  ([#2245](https://github.com/oasislabs/oasis-core/issues/2245))

  Initial support for fuzzing was added, along with an implementation of
  it for some of the consensus methods. The implementation uses
  oasis-core's demultiplexing and method dispatch mechanisms.

- Add storage backend fuzzing
  ([#2246](https://github.com/oasislabs/oasis-core/issues/2246))

  Based on the work done for consensus fuzzing, support was added to run fuzzing
  jobs on the storage api backend.

- Add `oasis-node unsafe-reset` sub-command which resets the node back to a
  freshly provisioned state, preserving any key material if it exists
  ([#2435](https://github.com/oasislabs/oasis-core/issues/2435))

- Add txsource
  ([#2478](https://github.com/oasislabs/oasis-core/issues/2478))

  The so-called "txsource" utility introduced in this PR is a starting point for
  something like a client that sends transactions for a long period of time, for
  the purpose of creating long-running tests.

  With this change is a preliminary sample "workload"--a DRBG-backed schedule of
  transactions--which transfers staking tokens around among a set of test
  accounts.

- Add consensus block and transaction metadata accessors
  ([#2482](https://github.com/oasislabs/oasis-core/issues/2482))

  In order to enable people to build "network explorers", we exposed some
  additional methods via the consensus API endpoint, specifically:

  - Consensus block metadata.
  - Access to raw consensus transactions within a block.
  - Stream of consensus blocks as they are finalized.

- Make maximum in-memory cache size for runtime storage configurable
  ([#2494](https://github.com/oasislabs/oasis-core/issues/2494))

  Previously the value of 64mb was always used as the size of the in-memory
  storage cache. This adds a new configuration parameter/command-line flag
  `--storage.max_cache_size` which configures the maximum size of the in-memory
  runtime storage cache.

- Undisable transfers for some senders
  ([#2498](https://github.com/oasislabs/oasis-core/issues/2498))

  Ostensibly for faucet purposes while we run the rest of the network with
  transfers disabled, this lets us identify a whitelist of accounts from which
  we allow transfers when otherwise transfers are disabled.

  Configure this with a map of allowed senders' public keys -> `true` in the
  new `undisable_transfers_from` field in the staking consensus parameters
  object along with `"disable_transfers": true`.

- Entity block signatures count tool
  ([#2500](https://github.com/oasislabs/oasis-core/issues/2500))

  The tool uses node consensus and registry API endpoints and computes the per
  entity block signature counts.

### Bug Fixes

- Reduce Badger in-memory cache sizes
  ([#2484](https://github.com/oasislabs/oasis-core/issues/2484))

  The default is 1 GiB per badger instance and we use a few instances so this
  resulted in some nice memory usage.

## 19.0 (2019-12-18)

### Process

- Start using the new Versioning and Release process for Oasis Core.
  ([#2419](https://github.com/oasislabs/oasis-core/issues/2419))

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
  https://github.com/oasislabs/oasis-core/issues/2457).
