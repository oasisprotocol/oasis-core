# Deploying a Runtime

Before proceeding, make sure to look at the [prerequisites] required for running
an Oasis Core environment followed by [build instructions] for the respective
environment (non-SGX or SGX), using the [`oasis-net-runner`] and see [runtime
documentation] for a general documentation on runtimes.

These instructions will show how to register and deploy a runtime node on a
local development network.

[prerequisites]: prerequisites.md
[build instructions]: building.md
[`oasis-net-runner`]: oasis-net-runner.md
[runtime documentation]: ../runtime/README.md

## Provision a Single Validator Node Network

Use the [`oasis-net-runner`] to provision a validator node network without any
registered runtimes.

<!-- markdownlint-disable line-length -->

```
mkdir /tmp/runtime-example

oasis-net-runner \
  --basedir.no_temp_dir \
  --basedir /tmp/runtime-example \
  --fixture.default.node.binary go/oasis-node/oasis-node \
  --fixture.default.setup_runtimes=false \
  --fixture.default.deterministic_entities \
  --fixture.default.fund_entities \
  --fixture.default.num_entities 2
```

<!-- markdownlint-enable line-length -->

The following steps should be run in a separate terminal window. To simplify the
instructions set up an `ADDR` environment variable pointing to the UNIX socket
exposed by the started node:

```
export ADDR=unix:/tmp/runtime-example/net-runner/network/validator-0/internal.sock
```

Confirm the network is running by listing all registered entities:

```
oasis-node registry entity list -a $ADDR -v
```

Should give output similar to:

<!-- markdownlint-disable line-length -->

```
{"v":2,"id":"JTUtHd4XYQjh//e6eYU7Pa/XMFG88WE+jixvceIfWrk=","nodes":["LQu4ZtFg8OJ0MC4M4QMeUR7Is6Xt4A/CW+PK/7TPiH0="]}
{"v":2,"id":"+MJpnSTzc11dNI5emMa+asCJH5cxBiBCcpbYE4XBdso="}
{"v":2,"id":"TqUyj5Q+9vZtqu10yw6Zw7HEX3Ywe0JQA9vHyzY47TU="}
```

<!-- markdownlint-enable line-length -->

In following steps we will register and run the [simple-keyvalue] runtime on the
network.

<!-- markdownlint-disable line-length -->
[simple-keyvalue]: https://github.com/oasisprotocol/oasis-core/tree/master/tests/runtimes/simple-keyvalue
<!-- markdownlint-enable line-length -->

## Initializing a Runtime

To generate and sign a runtime registration transaction that will initialize and
register the runtime we will use the `registry runtime gen_register` command.
When initializing a runtime we need to provide the runtime descriptor.

For additional information about runtimes and parameters see the [runtime
documentation] and [code reference].

Before generating the registration transaction, gather the following data and
set up environment variables to simplify instructions.

- `ENTITY_DIR` - Path to the entity directory created when starting the
  development network. This entity will be the runtime owner. The genesis used
  in the provisioning initial network step funds the all entities in entities.
  In the following instructions we will be using the `entity-2` entity (located
  in `/tmp/runtime-example/net-runner/network/entity-2/` directory).
- `ENTITY_ID` - ID of the entity that will be the owner of the runtime. You can
  get the entity ID from `$ENTITY_DIR/entity.json` file.
- `GENESIS_JSON` - Path to the genesis.json file used in the development
  network. (defaults to:
  `/tmp/runtime-example/net-runner/network/genesis.json`).
- `RUNTIME_ID` - See [runtime identifiers] on how to choose a runtime
  identifier. In this example we use
  `8000000000000000000000000000000000000000000000000000000001234567` which is a
  test identifier that will not work outside local tests.
- `RUNTIME_GENESIS_JSON` - Path to the runtime genesis state file. The runtime
  used in this example does not use a genesis file.
- `NONCE` - Entity account nonce. If you followed the guide, nonce `0` would be
  the initial nonce to use for the entity. Note: make sure to keep updating the
  nonce when generating new transactions. To query for current account nonce
  value use [stake account info] CLI.

```
export ENTITY_DIR=/tmp/runtime-example/net-runner/network/entity-2/
export ENTITY_ID=+MJpnSTzc11dNI5emMa+asCJH5cxBiBCcpbYE4XBdso=
export GENESIS_JSON=/tmp/runtime-example/net-runner/network/genesis.json
export RUNTIME_ID=8000000000000000000000000000000000000000000000000000000001234567
export RUNTIME_DESCRIPTOR=/tmp/runtime-example/runtime_descriptor.json
export NONCE=0
```

Prepare a runtime descriptor:

```
cat << EOF > "${RUNTIME_DESCRIPTOR}"
{
  "v": 2,
  "id": "${RUNTIME_ID}",
  "entity_id": "${ENTITY_ID}",
  "genesis": {
    "state_root": "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    "state": null,
    "storage_receipts": null,
    "round": 0
  },
  "kind": 1,
  "tee_hardware": 0,
  "versions": {
    "version": {}
  },
  "executor": {
    "group_size": 1,
    "group_backup_size": 0,
    "allowed_stragglers": 0,
    "round_timeout": 5,
    "max_messages": 32
  },
  "txn_scheduler": {
    "algorithm": "simple",
    "batch_flush_timeout": 1000000000,
    "max_batch_size": 1000,
    "max_batch_size_bytes": 16777216,
    "propose_batch_timeout": 5
  },
  "storage": {
    "group_size": 1,
    "min_write_replication": 1,
    "max_apply_write_log_entries": 100000,
    "max_apply_ops": 2,
    "checkpoint_interval": 10000,
    "checkpoint_num_kept": 2,
    "checkpoint_chunk_size": 8388608
  },
  "admission_policy": {
    "entity_whitelist": {
      "entities": {
        "${ENTITY_ID}": {}
      }
    }
  },
  "staking": {},
  "governance_model": "entity"
}
EOF
```

[runtime identifiers]: ../runtime/identifiers.md
[stake account info]: ../oasis-node/cli.md#info

```
oasis-node registry runtime gen_register \
  --transaction.fee.gas 1000 \
  --transaction.fee.amount 0 \
  --transaction.file /tmp/runtime-example/register_runtime.tx \
  --transaction.nonce $NONCE \
  --genesis.file $GENESIS_JSON \
  --signer.backend file \
  --signer.dir $ENTITY_DIR \
  --runtime.descriptor /tmp/runtime-example/runtime-descriptor.json
  --debug.dont_blame_oasis \
  --debug.allow_test_keys
```

After confirmation, this command outputs a signed transaction in the
`/tmp/runtime-example/register_runtime.tx` file. In the next step we will submit
the transaction to complete the runtime registration.

:::caution

When registering a runtime on a _non-development_ network you will likely want
to modify default parameters. Additionally, since we are running this on a debug
network, we had to enable the `debug.dont_blame_oasis` and
`debug.allow_test_keys` flags.

:::

<!-- markdownlint-disable line-length -->

[code reference]:
  https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#Runtime

<!-- markdownlint-enable line-length -->

## Submitting the Runtime Register Transaction

To register the runtime, submit the generated transaction.

```
oasis-node consensus submit_tx \
    --transaction.file /tmp/runtime-example/register_runtime.tx \
    --address $ADDR
```

## Confirm Runtime is Registered

To confirm the runtime is registered use the `registry runtime list` command.

```
oasis-node registry runtime list \
  --verbose \
  --include_suspended \
  --address $ADDR
```

Should give output similar to

```
{
  "v": 2,
  "id": "8000000000000000000000000000000000000000000000000000000001234567",
  "entity_id": "+MJpnSTzc11dNI5emMa+asCJH5cxBiBCcpbYE4XBdso=",
  "genesis": {
    "state_root": "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    "state": null,
    "storage_receipts": null,
    "round": 0
  },
  "kind": 1,
  "tee_hardware": 0,
  "versions": {
    "version": {}
  },
  "executor": {
    "group_size": 1,
    "group_backup_size": 0,
    "allowed_stragglers": 0,
    "round_timeout": 5,
    "max_messages": 32
  },
  "txn_scheduler": {
    "algorithm": "simple",
    "batch_flush_timeout": 1000000000,
    "max_batch_size": 1000,
    "max_batch_size_bytes": 16777216,
    "propose_batch_timeout": 5
  },
  "storage": {
    "group_size": 1,
    "min_write_replication": 1,
    "max_apply_write_log_entries": 100000,
    "max_apply_ops": 2,
    "checkpoint_interval": 10000,
    "checkpoint_num_kept": 2,
    "checkpoint_chunk_size": 8388608
  },
  "admission_policy": {
    "entity_whitelist": {
      "entities": {
        "+MJpnSTzc11dNI5emMa+asCJH5cxBiBCcpbYE4XBdso=": {}
      }
    }
  },
  "staking": {},
  "governance_model": "entity"
}
```

:::info

Since we did not setup any runtime nodes, the runtime
will get [suspended] until nodes for the runtime register.

:::

In the next step we will setup and run a runtime node.

[suspended]: ../runtime/README.md#suspending-runtimes

## Running a Runtime Node

We will now run a node that will act as a compute, storage and client node for
the runtime.

:::info

In a real word scenario there would be multiple nodes
running the runtime, each likely serving as a single type only.

:::

Before running the node, gather the following data parameters and set up
environment variables to simplify instructions.

- `RUNTIME_BINARY` - Path to the runtime binary that will be run on the node. We
  will use the [simple-keyvalue] runtime. If you followed the [build
  instructions] the built binary is available at
  `./target/default/debug/simple-keyvalue`.
- `SEED_NODE_ADDRESS` - Address of the seed node in the development network.
  Seed node address can be seen in the `oasis-net-runner` logs, when the network
  is initially provisioned.

<!-- markdownlint-disable line-length -->

```
export RUNTIME_BINARY=/workdir/target/default/debug/simple-keyvalue
export SEED_NODE_ADDRESS=<seed-node-tendermint-addr>@127.0.0.1:20000

# Runtime node data dir.
mkdir -m 0700 /tmp/runtime-example/runtime-node

# Start runtime node.
oasis-node \
  --datadir /tmp/runtime-example/runtime-node \
  --log.level debug \
  --log.format json \
  --log.file /tmp/runtime-example/runtime-node/node.log \
  --grpc.log.debug \
  --worker.registration.entity $ENTITY_DIR/entity.json \
  --genesis.file $GENESIS_JSON \
  --worker.storage.enabled \
  --worker.compute.enabled \
  --runtime.provisioner unconfined \
  --runtime.supported $RUNTIME_ID \
  --runtime.paths $RUNTIME_ID=$RUNTIME_BINARY \
  --consensus.tendermint.debug.addr_book_lenient \
  --consensus.tendermint.debug.allow_duplicate_ip \
  --consensus.tendermint.p2p.seed $SEED_NODE_ADDRESS \
  --debug.dont_blame_oasis \
  --debug.allow_test_keys
```

<!-- markdownlint-enable line-length -->

:::danger

This also enables unsafe debug-only flags which must never be used in a
production setting as they may result in node compromise.

:::

:::info

When running a runtime node in a production setting, the
`worker.p2p.addresses` and `worker.client.addresses` flags need to be configured
as well.

:::

Following steps should be run in a new terminal window.

## Updating Entity Nodes

Before the newly started runtime node can register itself as a runtime node, we
need to update the entity information in registry, to include the started node.

Before proceeding, gather the runtime node id and store it in a variable. If you
followed above instructions, the node id can be seen in
`/tmp/runtime-example/runtime-node/identity_pub.pem` (or using the [node control
status command]).

Update the entity and generate a transaction that will update the registry
state.

```
# NOTE: this ID is not generated deterministically make sure to change the ID
# with your node id.
export NODE_ID=NOPhD7UlMZBO8fNyo2xLFanlmvl+EmZ5s4mM2z9nEBg=

oasis-node registry entity update \
  --signer.dir $ENTITY_DIR  \
  --entity.node.id $NODE_ID

oasis-node registry entity gen_register \
  --genesis.file $GENESIS_JSON \
  --signer.backend file \
  --signer.dir $ENTITY_DIR \
  --transaction.file /tmp/runtime-example/update_entity.tx \
  --transaction.fee.gas 2000 \
  --transaction.fee.amount 0 \
  --transaction.nonce $NONCE \
  --debug.dont_blame_oasis \
  --debug.allow_test_keys
```

Submit the generated transaction:

```
oasis-node consensus submit_tx \
    --transaction.file /tmp/runtime-example/update_entity.tx \
    --address $ADDR
```

Confirm the entity in the registry has been updated by querying the registry
state:

<!-- markdownlint-disable line-length -->

```
oasis-node registry entity list -a $ADDR -v

{"v":1,"id":"JTUtHd4XYQjh//e6eYU7Pa/XMFG88WE+jixvceIfWrk=","nodes":["LQu4ZtFg8OJ0MC4M4QMeUR7Is6Xt4A/CW+PK/7TPiH0="]}
{"v":1,"id":"+MJpnSTzc11dNI5emMa+asCJH5cxBiBCcpbYE4XBdso=","nodes":["vWUfSmjrHSlN5tSSO3/Qynzx+R/UlwPV9u+lnodQ00c="]}
{"v":1,"id":"TqUyj5Q+9vZtqu10yw6Zw7HEX3Ywe0JQA9vHyzY47TU=","allow_entity_signed_nodes":true}
```

<!-- markdownlint-enable line-length -->

Node is now able to register and the runtime should get resumed, make sure this
happens by querying the registry for runtimes:

```
# Ensure node is registered
oasis-node registry node list -a $ADDR -v | grep "$NODE_ID"

# Ensure runtime is resumed.
oasis-node registry runtime list -a $ADDR -v
```

:::info

You might need to wait few seconds for an epoch
transition so that the node is registered and runtime gets resumed.

:::

[node control status command]: ../oasis-node/cli.md#status
