# Table of Contents

<!-- This is a table of contents used for GitBook. -->

## Development Setup

* Build Environment Setup and Building
  * [Prerequisites](setup/prerequisites.md)
  * [Building](setup/building.md)

* Running Tests and Development Networks
  * [Running Tests](setup/running-tests.md)
  * [Local Network Runner With a Simple Runtime](setup/oasis-net-runner.md)
  * [Single Validator Node Network](setup/single-validator-node-network.md)
  * [Deploying a Runtime](setup/deploying-a-runtime.md)

## High-Level Components

* [Consensus Layer](consensus/index.md)
  * [Transactions](consensus/transactions.md)
  * Services
    * [Epoch Time](consensus/epochtime.md)
    * [Random Beacon](consensus/beacon.md)
    * [Staking](consensus/staking.md)
    * [Registry](consensus/registry.md)
    * [Committee Scheduler](consensus/scheduler.md)
    * [Governance](consensus/governance.md)
    * [Root Hash](consensus/roothash.md)
    * [Key Manager](consensus/keymanager.md)
  * [Genesis Document](consensus/genesis.md)
  * [Transaction Test Vectors](consensus/test-vectors.md)
* [Runtime Layer](runtime/index.md)
  * [Runtime Host Protocol](runtime/runtime-host-protocol.md)
  * [Identifiers](runtime/identifiers.md)
  * [Messages](runtime/messages.md)
* Oasis Node
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

* [Architectural Decision Records](adr/index.md)
* [Release Process](release-process.md)
* [Versioning](versioning.md)
