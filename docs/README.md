# Oasis Core Developer Documentation

![Architecture](images/oasis-core-high-level.svg)

## Development Setup

Here are instructions on how to set up the local build environment, run the
tests and some examples on how to prepare test networks for local development of
Oasis Core components.

<!-- markdownlint-disable line-length -->

* Build Environment Setup and Building
  * [Prerequisites](development-setup/prerequisites.md)
  * [Building](development-setup/building.md)
* Running Tests and Development Networks
  * [Running Tests](development-setup/running-tests.md)
  * [Local Network Runner With a Simple Runtime](development-setup/oasis-net-runner.md)
  * [Single Validator Node Network](development-setup/single-validator-node-network.md)
  * [Deploying a Runtime](development-setup/deploying-a-runtime.md)

<!-- markdownlint-enable line-length -->

## High-Level Components

At the highest level, Oasis Core is divided into two major layers: the
_consensus layer_ and the _runtime layer_ as shown on the figure above.

The idea behind the consensus layer is to provide a minimal set of features
required to securely operate independent runtimes running in the runtime layer.
It provides the following services:

* Epoch-based time keeping and a random beacon.
* Basic staking operations required to operate a PoS blockchain.
* An entity, node and runtime registry that distributes public keys and
  metadata.
* Runtime committee scheduling, commitment processing and minimal state keeping.

On the other side, each runtime defines its own state and state transitions
independent from the consensus layer, submitting only short proofs that
computations were performed and results were stored. This means that runtime
state and logic are completely decoupled from the consensus layer, and the
consensus layer only provides information on what state (summarized by a
cryptographic hash of a Merklized data structure) is considered canonical at any
given point in time.

See the following sections for more details on specific components and their
implementations.

* [Consensus Layer](consensus/README.md)
  * [Transactions](consensus/transactions.md)
  * Services
    * [Epoch Time](consensus/services/epochtime.md)
    * [Random Beacon](consensus/services/beacon.md)
    * [Staking](consensus/services/staking.md)
    * [Registry](consensus/services/registry.md)
    * [Committee Scheduler](consensus/services/scheduler.md)
    * [Governance](consensus/services/governance.md)
    * [Root Hash](consensus/services/roothash.md)
    * [Key Manager](consensus/services/keymanager.md)
  * [Genesis Document](consensus/genesis.md)
  * [Transaction Test Vectors](consensus/test-vectors.md)
* [Runtime Layer](runtime/README.md)
  * [Operation Model](runtime/README.md#operation-model)
  * [Runtime Host Protocol](runtime/runtime-host-protocol.md)
  * [Identifiers](runtime/identifiers.md)
  * [Messages](runtime/messages.md)
* Oasis Node (`oasis-node`)
  * [RPC](oasis-node/rpc.md)
  * [Metrics](oasis-node/metrics.md)
  * [CLI](oasis-node/cli.md)

## Common Functionality

* [Serialization](encoding.md)
* [Cryptography](crypto.md)
* Protocols
  * [Authenticated gRPC](authenticated-grpc.md)
* [Merklized Key-Value Store (MKVS)](mkvs.md)

## Processes

* [Architectural Decision Records](https://github.com/oasisprotocol/adrs)
* [Release Process](release-process.md)
* [Versioning](versioning.md)
* [Security](SECURITY.md)
