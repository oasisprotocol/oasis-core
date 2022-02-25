# Single Validator Node Network

It is possible to provision a local "network" consisting of a single validator
node. This may be useful for specific development use cases.

Before proceeding, make sure to look at the [prerequisites] required for running
an Oasis Core environment followed by [build instructions] for the respective
environment (non-SGX or SGX). The following sections assume that you have
successfully completed the required build steps.

:::danger

These instructions are for a development-only instance, do not use them
for setting up any kind of production instances as they are unsafe and will
result in insecure configurations leading to node compromise.

:::

[prerequisites]: prerequisites.md
[build instructions]: building.md

## Provisioning an Entity

To provision an [entity] we first prepare an empty directory under
`/path/to/entity` and then initialize the entity:

```
mkdir -p /path/to/entity
cd /path/to/entity
oasis-node registry entity init --signer.backend file --signer.dir .
```

[entity]: ../consensus/services/registry.md#entities-and-nodes

## Provisioning a Node

To provision a [node] we first prepare an empty directory under `/path/to/node`
and the initialize the node. The node is provisioned as a validator.

```
mkdir -p /path/to/node
cd /path/to/node
oasis-node registry node init \
  --signer.backend file \
  --signer.dir /path/to/entity \
  --node.consensus_address 127.0.0.1:26656 \
  --node.is_self_signed \
  --node.role validator
```

After the node is provisioned we proceed with updating the [entity whitelist]
so that the node will be able to register itself:

```
oasis-node registry entity update \
  --signer.backend file \
  --signer.dir /path/to/entity \
  --entity.node.descriptor /path/to/node/node_genesis.json
```

[node]: ../consensus/services/registry.md#entities-and-nodes
[entity whitelist]: ../consensus/services/registry.md#register-node

## Creating a Test Genesis Document

To create a test genesis document for your development "network" use the
following commands:

```
mkdir -p /path/to/genesis
cd /path/to/genesis
oasis-node genesis init \
  --chain.id test \
  --entity /path/to/entity/entity_genesis.json \
  --node /path/to/node/node_genesis.json \
  --debug.dont_blame_oasis \
  --debug.test_entity \
  --debug.allow_test_keys \
  --registry.debug.allow_unroutable_addresses \
  --staking.token_symbol TEST
```

:::danger

This enables unsafe debug-only flags which must never be used in a
production setting as they may result in node compromise.

:::

## Running the Node

To run the single validator node, use the following command:

```
oasis-node \
  --datadir /path/to/node \
  --genesis.file /path/to/genesis/genesis.json \
  --worker.registration.entity /path/to/entity/entity.json \
  --consensus.validator \
  --debug.dont_blame_oasis \
  --debug.allow_test_keys \
  --log.level debug
```

:::danger

This enables unsafe debug-only flags which must never be used in a
production setting as they may result in node compromise.

:::

## Using the Node CLI

The `oasis-node` exposes [an RPC interface] via a UNIX socket located in its
data directory (e.g., under `/path/to/node/internal.sock`). To simplify the
following instructions set up an `ADDR` environment variable pointing to it:

```
export ADDR=unix:/path/to/node/internal.sock
```

This can then be used to execute CLI commands against the running node (in a
separate terminal). For example to show all registered entities:

```
oasis-node registry entity list -a $ADDR -v
```

Giving output similar to:

<!-- markdownlint-disable line-length -->
```
{"v":1,"id":"UcxpyD0kSo/5keRqv8pLypM/Mg5S5iULRbt7Uf73vKQ=","nodes":["jo+quvaFYAP4Chyf1PRqCZZObqpDeJCxfBzTyghiXxs="]}
{"v":1,"id":"TqUyj5Q+9vZtqu10yw6Zw7HEX3Ywe0JQA9vHyzY47TU=","allow_entity_signed_nodes":true}
```
<!-- markdownlint-enable line-length -->

Or getting a list of all staking accounts:

```
oasis-node stake list -a $ADDR
```

Giving output similar to:

```
oasis1qzzd6khm3acqskpxlk9vd5044cmmcce78y5l6000
oasis1qz3xllj0kktskjzlk0qacadgwpfe8v7sy5kztvly
oasis1qrh4wqfknrlvv7whjm7mjsjlvka2h35ply289pp2
```

[an RPC interface]: ../oasis-node/rpc.md
