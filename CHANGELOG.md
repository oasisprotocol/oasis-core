# Change Log

All notables changes to this project are documented in this file.

The format is inspired by [Keep a Changelog].

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/

<!-- NOTE: towncrier will not alter content above the TOWNCRIER line below. -->

<!-- TOWNCRIER -->

## 20.1 (2020-01-14)

### Features

- go/worker/txnscheduler: Check transactions before queuing them
  ([#2502](https://github.com/oasislabs/oasis-core/issues/2502))

  The transaction scheduler can now optionally run runtimes and
  check transactions before scheduling them (see issue #1963).
  This functionality is disabled by default, enable it with
  `worker.txn_scheduler.check_tx.enabled`.

### Bug Fixes

- go/runtime/client: Return empty sequences instead of nil.
  ([#2542](https://github.com/oasislabs/oasis-core/issues/2542))

  The runtime client endpoint should return empty sequences instead of `nil` as serde doesn't know how
  to decode a `NULL` when the expected type is a sequence.

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

- Remove staking-related roothash messages.
  ([#2377](https://github.com/oasislabs/oasis-core/issues/2377))

  There is no longer a plan to support direct manipulation of the staking accounts
  from the runtimes in order to isolate the runtimes from corrupting the
  consensus layer.

  To reduce complexity, the staking-related roothash messages were removed. The
  general roothash message mechanism stayed as-is since it may be useful in the
  future, but any commits with non-empty messages are rejected for now.

- Refactoring of roothash genesis block for runtime.
  ([#2426](https://github.com/oasislabs/oasis-core/issues/2426))

  - `RuntimeGenesis.Round` field was added to the roothash block for the runtime
  which can be set by `--runtime.genesis.round` flag.
  - The `RuntimeGenesis.StorageReceipt` field was replaced by `StorageReceipts` list,
  one for each storage node.
  - Support for `base64` encoding/decoding of `Bytes` was added in rust.

- When registering a new runtime, require that the given key manager ID points
  to a valid key manager in the registry.
  ([#2459](https://github.com/oasislabs/oasis-core/issues/2459))

- Remove `oasis-node debug dummy` sub-commands.
  ([#2492](https://github.com/oasislabs/oasis-core/issues/2492))

  These are only useful for testing, and our test harness has a internal Go API
  that removes the need to have this functionality exposed as a sub-command.

- Make storage per-runtime.
  ([#2494](https://github.com/oasislabs/oasis-core/issues/2494))

  Previously there was a single storage backend used by `oasis-node` which required that a single
  database supported multiple namespaces for the case when multiple runtimes were being used in a
  single node.

  This change simplifies the storage database backends by removing the need for backends to implement
  multi-namespace support, reducing overhead and cleanly separating per-runtime state.

  Due to this changing the internal database format, this breaks previous (compute node) deployments
  with no way to do an automatic migration.

### Features

- Add `oasis-node debug storage export` sub-command.
  ([#1845](https://github.com/oasislabs/oasis-core/issues/1845))

- Add fuzzing for consensus methods.
  ([#2245](https://github.com/oasislabs/oasis-core/issues/2245))

  Initial support for fuzzing was added, along with an implementation of
  it for some of the consensus methods. The implementation uses
  oasis-core's demultiplexing and method dispatch mechanisms.

- Add storage backend fuzzing.
  ([#2246](https://github.com/oasislabs/oasis-core/issues/2246))

  Based on the work done for consensus fuzzing, support was added to run fuzzing
  jobs on the storage api backend.

- Add `oasis-node unsafe-reset` sub-command which resets the node back to a
  freshly provisioned state, preserving any key material if it exists.
  ([#2435](https://github.com/oasislabs/oasis-core/issues/2435))

- Add txsource.
  ([#2478](https://github.com/oasislabs/oasis-core/issues/2478))

  The so-called "txsource" utility introduced in this PR is a starting point for something like a client that sends
  transactions for a long period of time, for the purpose of creating long-running tests.

  With this change is a preliminary sample "workload"--a DRBG-backed schedule of transactions--which transfers staking
  tokens around among a set of test accounts.

- Add consensus block and transaction metadata accessors.
  ([#2482](https://github.com/oasislabs/oasis-core/issues/2482))

  In order to enable people to build "network explorers", we exposed some
  additional methods via the consensus API endpoint, specifically:

  - Consensus block metadata.
  - Access to raw consensus transactions within a block.
  - Stream of consensus blocks as they are finalized.

- Make maximum in-memory cache size for runtime storage configurable.
  ([#2494](https://github.com/oasislabs/oasis-core/issues/2494))

  Previously the value of 64mb was always used as the size of the in-memory storage cache. This adds a
  new configuration parameter/command-line flag `--storage.max_cache_size` which configures the
  maximum size of the in-memory runtime storage cache.

- Undisable transfers for some senders.
  ([#2498](https://github.com/oasislabs/oasis-core/issues/2498))

  Ostensibly for faucet purposes while we run the rest of the network with transfers disabled,
  this lets us identify a whitelist of accounts from which we allow transfers when otherwise transfers are disabled.

  Configure this with a map of allowed senders' public keys -> `true` in the new `undisable_transfers_from` field in the
  staking consensus parameters object along with `"disable_transfers": true`.

- Entity block signatures count tool.
  ([#2500](https://github.com/oasislabs/oasis-core/issues/2500))

  The tool uses node consensus and registry API endpoints and computes the per
  entity block signature counts.

### Bug Fixes

- Reduce Badger in-memory cache sizes.
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
