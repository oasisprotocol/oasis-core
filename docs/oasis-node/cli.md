# `oasis-node` CLI

## Setup

### Server commands

To run a command that requires a connection to an online Oasis node (i.e. the
`server`), you need to either:

- change the working directory to where the internal Oasis node UNIX socket is
  located (e.g. `/serverdir/node/`) before executing the command, or
- pass the `-a $ADDR` flag where `ADDR` represents the path to the internal
  Oasis node UNIX socket prefixed with `unix:`
  (e.g.`unix:/serverdir/node/internal.sock`).

Here are some examples of Oasis Node CLI commands that need a connection to an
online Oasis node:

- `oasis-node stake info`: Shows general staking information.
- `oasis-node stake list`: Lists all accounts with positive balance.
- `oasis-node stake account info`: Shows detailed information for an account.
- `oasis-node consensus submit_tx`: Submits a pre-generated transaction to the
  network.

### Local commands

The following commands are intended to be run on your local machine and only
need access to the [network's current genesis file] and your signer's private
key:

- `oasis-node stake account gen_transfer`
- `oasis-node stake account gen_escrow`
- `oasis-node stake account gen_reclaim_escrow`
- `oasis-node stake account gen_amend_commission_schedule`

:::danger

We strongly suggest that you do not use any entity/staking account that is
generated with the file-based signer on the Mainnet.

In case you need to use the file-based signer, make sure you only use it on an
[offline/air-gapped machine]. Gaining access to your entity's/staking account's
private key can compromise your tokens.

:::

[network's current genesis file]:
  https://github.com/oasisprotocol/docs/blob/main/docs/node/mainnet/README.md
[offline/air-gapped machine]:
  https://en.wikipedia.org/wiki/Air_gap_\(networking\)

### JSON pretty-printing

We will pipe the output of commands that return JSON through the
Python's [`json.tool` module] to pretty-print it.

:::caution

Be aware that [jq](https://stedolan.github.io/jq/), the popular JSON CLI tool,
converts all numbers to
[IEEE 754 64-bit values](https://github.com/stedolan/jq/wiki/FAQ#caveats) which
can result in silent loss of precision and/or other changes.

Hence, we recommend avoiding its usage until this issue is resolved.

:::

[`json.tool` module]:
  https://docs.python.org/3/library/json.html#module-json.tool

### Common CLI Flags

#### Base Flags

All commands for generating and signing transactions need the following base
flags set:

- `--genesis.file`: Path to the genesis file, e.g. `/localhostdir/genesis.json`.

For convenience, set the `GENESIS_FILE` environment value to its value, e.g.:

```bash
  GENESIS_FILE=/localhostdir/genesis.json
```

- `--signer.dir`: Path to entity's artifacts directory,
  e.g. `entity-$LEDGER_INDEX` or `/localhostdir/entity/`

#### Signer Flags

Currently, we provide two options for signing transactions:

- **Ledger-based signer.**
  
  You will need to set it up as described in our [Oasis Core Ledger] docs.

- **File-based signer.**

  You will need to create your Entity as described in the
  [Running a Node on the Network] docs and set the following flags:

  - `--signer.backend file`: Specifies use of the file signer.

[Oasis Core Ledger]: https://github.com/oasisprotocol/oasis-core-ledger/blob/master/docs/usage/transactions.md
[Running a Node on the Network]: https://github.com/oasisprotocol/docs/blob/main/docs/node/run-your-node/validator-node.mdx#creating-your-entity

#### Storing Base and Signer flags in an Environment Variable

To make the transaction commands shorter and avoid typing errors, one can create
an environment variable, e.g. `TX_FLAGS`, with all the
[Base Flags](#base-flags) and [Signer Flags](#signer-flags)
configured for his particular set up.

For example, one could set `TX_FLAGS` for a Ledger device like below (make sure
all `LEDGER_*` environment variables are set appropriately):

```bash
TX_FLAGS=(--genesis.file "$GENESIS_FILE"
  --signer.dir /localhostdir/entity
  --signer.backend plugin
  --signer.plugin.name ledger
  --signer.plugin.path "$LEDGER_SIGNER_PATH"
)
```

Or, one could set `TX_FLAGS` like below to use a file signer:

```bash
TX_FLAGS=(--genesis.file "$GENESIS_FILE"
  --signer.backend file
  --signer.dir /localhostdir/entity/
)
```

#### Common Transaction Flags

When generating a transaction, one needs to set the following transaction flags
as appropriate for a given transaction:

* `--stake.amount`: Amount of base units to transfer, escrow, burn, etc.
* `--transaction.file`: Path to the file where to store the generated
  transaction.
* `--transaction.nonce`: Incremental number that must be unique for each
  account's transaction. To get your current account's nonce, see
  [Checking Your Account nonce](#nonce) doc.
* `--transaction.fee.gas`: Maximum amount of gas (in *gas units*) a transaction
  can spend.

Gas costs for different staking transactions are specified by the
`staking.params.gas_costs` consensus parameter.

To obtain its value from the genesis file, run:

```bash
  cat $GENESIS_FILE | \
    python3 -c 'import sys, json; \
    print(json.dumps(json.load(sys.stdin)["staking"]["params"]["gas_costs"], indent=4))'
```

- `--transaction.fee.amount`: Amount of base units we will pay as a fee for a
  transaction.

Note that specifying a transaction's fee amount (via `--transaction.fee.amount`)
and maximum gas amount (via `--transaction.fee.gas`) implicitly defines the
*gas price* (in base units):

```
gas_price = fee_amount / gas_amount
```

Gas price tells how much base units we are willing to pay for one gas unit.

Consensus validators can configure their own *minimum gas price*
(via `consensus.tendermint.min_gas_price` configuration flag) and will refuse to
process transactions that have their gas price set below their minimum gas
price.

:::info

Currently, there is no mechanism to discover what minimum gas prices are used
by validators.

For more details, see
[Oasis Core #2526](https://github.com/oasisprotocol/oasis-core/issues/2526).

:::

## `control`

### `status`

Run

```sh
oasis-node control status --address unix:/path/to/node/internal.sock
```

to get information like the following (example taken from a runtime compute
node):

<!-- markdownlint-disable line-length -->
```json
{
  "software_version": "21.3",
  "identity": {
    "node": "iWq6Nft6dU2GWAr9U7ICbhXWwmAINIniKzMMblSo5Xs=",
    "p2p": "dGd+pGgIlkJb0dnkBQ7vI2EWWG81pF5M1G+jL2/6pyA=",
    "consensus": "QaMdKVwX1da0Uf82cp0DDukQQwrSjr8BwlIxc//ANE8=",
    "tls": [
      "Kj8ANHwfMzcWoA1vx0OMhn4oGv8Y0vc46xMOdQUIh5c=",
      "1C8rWqyuARkSxNXuPbDPh9XID/SiYAU3GxGk6nMwR0Q="
    ]
  },
  "consensus": {
    "version": {
      "major": 4
    },
    "backend": "tendermint",
    "features": 3,
    "node_peers": [
      "5ab8074ce3053ef9b72d664c73e39972241442e3@57.71.39.73:26658",
      "abb66e8780f3815d87bad488a2892b4d4b2221e3@108.15.34.59:50716"
    ],
    "latest_height": 5960191,
    "latest_hash": "091c29c3d588c52421a4f215268c6b4ab1a7762c429a98fec5de9251f8907add",
    "latest_time": "2021-09-24T21:42:29+02:00",
    "latest_epoch": 10489,
    "latest_state_root": {
      "ns": "0000000000000000000000000000000000000000000000000000000000000000",
      "version": 5960190,
      "root_type": 1,
      "hash": "c34581dcec59d80656d6082260d63f3206aef0a1b950c1f2c06d1eaa36a22ec3"
    },
    "genesis_height": 5891596,
    "genesis_hash": "e9d9fb99baefc3192a866581c35bf43d7f0499c64e1c150171e87b2d5dc35087",
    "last_retained_height": 5891596,
    "last_retained_hash": "e9d9fb99baefc3192a866581c35bf43d7f0499c64e1c150171e87b2d5dc35087",
    "chain_context": "9ee492b63e99eab58fd979a23dfc9b246e5fc151bfdecd48d3ba26a9d0712c2b",
    "is_validator": true
  },
  "runtimes": {
    "0000000000000000000000000000000000000000000000000000000000000001": {
      "descriptor": {
        "v": 2,
        "id": "0000000000000000000000000000000000000000000000000000000000000001",
        "entity_id": "Ldzg8aeLiUBrMYxidd5DqEzpamyV2cprmRH0pG8d/Jg=",
        "genesis": {
          "state_root": "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
          "state": null,
          "storage_receipts": null,
          "round": 0
        },
        "kind": 1,
        "tee_hardware": 0,
        "versions": {
          "version": {
            "minor": 2
          }
        },
        "executor": {
          "group_size": 3,
          "group_backup_size": 3,
          "allowed_stragglers": 1,
          "round_timeout": 5,
          "max_messages": 256
        },
        "txn_scheduler": {
          "algorithm": "simple",
          "batch_flush_timeout": 1000000000,
          "max_batch_size": 100,
          "max_batch_size_bytes": 1048576,
          "propose_batch_timeout": 2
        },
        "storage": {
          "group_size": 3,
          "min_write_replication": 2,
          "max_apply_write_log_entries": 10000,
          "max_apply_ops": 2,
          "checkpoint_interval": 100,
          "checkpoint_num_kept": 2,
          "checkpoint_chunk_size": 8388608
        },
        "admission_policy": {
          "any_node": {}
        },
        "constraints": {
          "executor": {
            "backup-worker": {
              "max_nodes": {
                "limit": 1
              },
              "min_pool_size": {
                "limit": 3
              }
            },
            "worker": {
              "max_nodes": {
                "limit": 1
              },
              "min_pool_size": {
                "limit": 3
              }
            }
          },
          "storage": {
            "worker": {
              "max_nodes": {
                "limit": 1
              },
              "min_pool_size": {
                "limit": 3
              }
            }
          }
        },
        "staking": {},
        "governance_model": "entity"
      },
      "latest_round": 1355,
      "latest_hash": "2a11820c0524a8a753f7f4a268ee2d0a4f4588a89121f92a43f4be9cc6acca7e",
      "latest_time": "2021-09-24T21:41:29+02:00",
      "latest_state_root": {
        "ns": "0000000000000000000000000000000000000000000000000000000000000000",
        "version": 1355,
        "root_type": 1,
        "hash": "45168e11548ac5322a9a206abff4368983b5cf676b1bcb2269f5dfbdf9df7be3"
      },
      "genesis_round": 0,
      "genesis_hash": "aed94c03ebd2d16dfb5f6434021abf69c8c15fc69b6b19554d23da8a5a053776",
      "committee": {
        "latest_round": 1355,
        "latest_height": 5960180,
        "last_committee_update_height": 5960174,
        "executor_roles": [
          "worker",
          "backup-worker"
        ],
        "storage_roles": [
          "worker"
        ],
        "is_txn_scheduler": false,
        "peers": [
          "/ip4/57.71.39.73/tcp/41002/p2p/12D3KooWJvL8mYzHbcLtj91bf5sHhtrB7C8CWND5sV6Kk24eUdpQ",
          "/ip4/108.67.32.45/tcp/26648/p2p/12D3KooWBKgcH7TGMSLuxzLxK41nTwk6DsxHRpb7HpWQXJzLurcv"
        ]
      },
      "storage": {
        "last_finalized_round": 1355
      }
    }
  },
  "registration": {
    "last_registration": "2021-09-24T21:41:08+02:00",
    "descriptor": {
      "v": 1,
      "id": "iWq6Nft6dU2GWAr9U7ICbhXWwmAINIniKzMMblSo5Xs=",
      "entity_id": "4G4ISI8hANvMRYTbxdXU+0r9m/6ZySHERR+2RDbNOU8=",
      "expiration": 10491,
      "tls": {
        "pub_key": "Kj8ANHwfMzcWoA1vx0OMhn4oGv8Y0vc46xMOdQUIh5c=",
        "next_pub_key": "1C8rWqyuARkSxNXuPbDPh9XID/SiYAU3GxGk6nMwR0Q=",
        "addresses": [
          "Kj8ANHwfMzcWoA1vx0OMhn4oGv8Y0vc46xMOdQUIh5c=@128.89.215.24:30001",
          "1C8rWqyuARkSxNXuPbDPh9XID/SiYAU3GxGk6nMwR0Q=@128.89.215.24:30001"
        ]
      },
      "p2p": {
        "id": "dGd+pGgIlkJb0dnkBQ7vI2EWWG81pF5M1G+jL2/6pyA=",
        "addresses": [
          "159.89.215.24:30002"
        ]
      },
      "consensus": {
        "id": "QaMdKVwX1da0Uf82cp0DDukQQwrSjr8BwlIxc//ANE8=",
        "addresses": [
          "dGd+pGgIlkJb0dnkBQ7vI2EWWG81pF5M1G+jL2/6pyA=@128.89.215.24:26656"
        ]
      },
      "beacon": {
        "point": "BHg8TOqKD4wV8UCu9nICvJt7rhXFd8CxXuYiHa6X/NnzlIndzGNEJyyTr00s5rgKwX25yPmv+r2xRFbcQK6hGLE="
      },
      "runtimes": [
        {
          "id": "0000000000000000000000000000000000000000000000000000000000000001",
          "version": {
            "minor": 2
          },
          "capabilities": {},
          "extra_info": null
        }
      ],
      "roles": "compute,storage,validator"
    },
    "node_status": {
      "expiration_processed": false,
      "freeze_end_time": 0,
      "election_eligible_after": 9810
    }
  },
  "pending_upgrades": []
}
```
<!-- markdownlint-enable line-length -->

## `genesis`

### `check`

To check if a given [genesis file] is valid, run:

```sh
oasis-node genesis check --genesis.file /path/to/genesis.json
```

:::info

This also checks if the genesis file is in the [canonical form].

:::

### `dump`

To dump the state of the network at a specific block height, e.g. 717600, to a
[genesis file], run:

```sh
oasis-node genesis dump \
  --address unix:/path/to/node/internal.sock \
  --genesis.file /path/to/genesis_dump.json \
  --height 717600
```

:::caution

You must only run the following command after the given block height has been
reached on the network.

:::

### `init`

To initialize a new [genesis file] with the given chain id and [staking token
symbol], run:

```sh
oasis-node genesis init --genesis.file /path/to/genesis.json \
  --chain.id "name-of-my-network" \
  --staking.token_symbol TEST
```

:::info

You can set a lot of parameters for the various [consensus layer services].

To see the full list, run:

```sh
oasis-node genesis init --help
```

:::

[genesis file]: ../consensus/genesis.md#genesis-file
[canonical form]: ../consensus/genesis.md#canonical-form
[consensus layer services]: ../consensus/README.md
[staking token symbol]: ../consensus/services/staking.md#tokens-and-base-units

## `stake`

### `account`

#### `info`

Run

```sh
oasis-node stake account info \
  --stake.account.address <account address> \
  --address unix:/path/to/node/internal.sock
```

to get staking information for a specific account:

```
General Account:
  Balance: TEST 0.0
  Nonce: 0
Escrow Account:
  Active:
    Balance: TEST 0.0
    Total Shares: 0
  Debonding:
    Balance: TEST 0.0
    Total Shares: 0
  Commission Schedule:
    Rates: (none)
    Rate Bounds: (none)
  Stake Accumulator:
    Claims:
      - Name: registry.RegisterEntity
        Staking Thresholds:
          - Global: entity
      - Name: registry.RegisterNode.LQu4ZtFg8OJ0MC4M4QMeUR7Is6Xt4A/CW+PK/7TPiH0=
        Staking Thresholds:
          - Global: node-validator
```

### `list`

To list all staking accounts with positive balance, run:

```bash
oasis-node stake list \
  --address unix:/path/to/node/internal.sock
```

This will list all accounts' addresses, e.g.:

```
oasis1qqqfalz4xars9nxn0mjy8fcf9quqg8ml0szm5ped
oasis1qqqd4wrmk8z9p3hz0vyc6zy3khx3gqnckywyg2s5
oasis1qqqul8678xs9tnj74x54k8ch2qdh7jveeswqf67j
oasis1qqzrcyed78mkxmt9qpv3pemsugknnhvnpv8v5vc3
oasis1qqz0qcmy932p69493qdkszcf9emgl55azys3xr8f
oasis1qq95xthkg20ra6ue8zyngqkkm92xqkvrms88axkj
oasis1qq9meupznk90d4lgluvcaqa27ggs55dscc6msc33
oasis1qq9acq6v5knfmatc9fvuwyzlexs0f7j3uvarusu6
oasis1qqxqlpfslwuuh5342qnstymyutancj7csucxv2ec
oasis1qqxmp9lggptm0pt23za7g5cfg2hzspezcumw7c3j
oasis1qq89qxh538sunk6p2fca487pfsy0ncxk9q4xf2un
oasis1qq8hgj2yzssawtpfqr8utj6d57k9zvx3wc989kqm
oasis1qq8atykwecy3p5rnspkweapzz847exaqwyv80wgx
oasis1qqgv5rxl4w27l89rf4j5dv8392kh42wt35yn0as6
oasis1qqg0h3mt7klha4w2kxjvsktv5ke6suuwpg8rvpdh
oasis1qqf3ctyg49tnwclksxun3dzhrv4zuww7hu7w3cul
oasis1qqfasfrrx2tae50kcy8mcclhp0kqymswsqnqytyg
oasis1qq2rlaz3yjfk8gtdhnrfkrz5rrxjnnrzeq7mst0r

... output trimmed ...
```

For more information on account's address format, see the
[Accounts][staking accounts] section of the staking service documentation.

[staking accounts]: ../consensus/services/staking.md#accounts

### `nonce`

To get more a particular staking account's, e.g.
`oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx`, nonce, run:

```bash
oasis-node stake account nonce \
  --address unix:/path/to/node/internal.sock \
  --stake.account.address oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx
```

#### Get Your Entity's Nonce

:::info

This example assumes you have the [jq](https://stedolan.github.io/jq/) tool installed on your system.

:::

If you want to get your entity's nonce, you can use the following combination of commands:

```bash
ENTITY_DIR=<PATH-TO-YOUR-ENTITY>
ADDRESS=$(oasis-node stake pubkey2address --public_key \
  $(cat $ENTITY_DIR/entity.json | jq .id -r))
NONCE=$(oasis-node stake account nonce --stake.account.address $ADDRESS --address unix:/path/to/node/internal.sock)
```

where `<PATH-TO-YOUR-ENTITY>` is the path to your entity's descriptor, e.g. `/serverdir/node/entity/`.

### `pubkey2address`

Run

```sh
oasis-node stake pubkey2address --public_key <public_key>
```

to get [staking account address][staking accounts] from an entity or the node's
public key. Example response:

```
oasis1qqncl383h8458mr9cytatygctzwsx02n4c5f8ed7
```

:::info

You can find your entity's ID in the `id` field of the `entity.json` file.

:::

### `gen_transfer`

Let's assume:

- `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6` is our staking account
  address,
- `oasis1qr3jc2yfhszpyy0daha2l9xjlkrxnzas0uaje4t3` is the destination's staking
  account address.

:::info

To convert your entity's ID to a staking account address, see the
[Obtain Account Address From Entity's ID](#pubkey2address) section.

:::

#### Query Our Account's Info

To query our staking account's information, use the following command:

```bash
oasis-node stake account info \
  --address unix:/path/to/node/internal.sock \
  --stake.account.address oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6
```

:::info

For a detailed explanation on querying account information, see the
[Get Info](#info) section.

:::

Before the transaction, this outputs:

```
General Account:
  Balance: ROSE 601.492492765
  Nonce:   7
Escrow Account:
  Active:
    Balance:      ROSE 11242.38481664
    Total Shares: 10000000000000
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

We can observe that:

- General account's balance is ~601 tokens.
- Account's nonce is 7.
- \~11242 tokens are actively bounded to the escrow account.
- The amount of tokens that are currently debonding is 0.

#### Query Destination Account's Info

To query the destination account's information, use the following command:

```bash
oasis-node stake account info \
  --address unix:/path/to/node/internal.sock \
  --stake.account.address oasis1qr3jc2yfhszpyy0daha2l9xjlkrxnzas0uaje4t3
```

Before the transaction, this outputs:

```
General Account:
  Balance: ROSE 0.0
  Nonce:   1030
Escrow Account:
  Active:
    Balance:      ROSE 0.0
    Total Shares: 0
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

We can observe that both, the general account and the escrow account (actively
bounded and debonding), have a balance of 0 tokens.

#### Generate a Transfer Transaction

Let's generate a transfer transaction of 170 tokens, (i.e. 170 * 10^9 base
units), from our account to the chosen destination account and store it to
`tx_transfer.json`:

```bash
oasis-node stake account gen_transfer \
  "${TX_FLAGS[@]}" \
  --stake.amount 170000000000 \
  --stake.transfer.destination oasis1qr3jc2yfhszpyy0daha2l9xjlkrxnzas0uaje4t3 \
  --transaction.file tx_transfer.json \
  --transaction.nonce 7 \
  --transaction.fee.gas 1000 \
  --transaction.fee.amount 2000
```

This will output a preview of the generated transaction:

```
You are about to sign the following transaction:
  Nonce:  7
  Fee:
    Amount: ROSE 0.000002
    Gas limit: 1000
    (gas price: ROSE 0.000000002 per gas unit)
  Method: staking.Transfer
  Body:
    To:     oasis1qr3jc2yfhszpyy0daha2l9xjlkrxnzas0uaje4t3
    Amount: ROSE 170.0
Other info:
  Genesis document's hash: 976c302f696e417bd861b599e79261244f4391f3887a488212ee122ca7bbf0a8
```

and ask you for confirmation.

#### Submit the Transaction

To submit the generated transaction, we need to copy `tx_transfer.json` to the
online Oasis node (i.e. the `server`) and submit it from there:

```bash
oasis-node consensus submit_tx \
  --address unix:/path/to/node/internal.sock \
  --transaction.file tx_transfer.json
```

#### Query Both Accounts' Info

Let's check both accounts' info, first ours:

```
General Account:
  Balance: ROSE 431.492490765
  Nonce:   8
Escrow Account:
  Active:
    Balance:      ROSE 11242.38481664
    Total Shares: 10000000000000
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

and then the destination's:

```
General Account:
  Balance: ROSE 170.0
  Nonce:   1030
Escrow Account:
  Active:
    Balance:      ROSE 0.0
    Total Shares: 0
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

We can observe that:

- Our general balance decreased by 170.000002 tokens. The 0.000002 token corresponds to the fee that we specified we will pay for this transaction.
- Our account's nonce increased to 8.
- Destination account's general balance increased by 170 tokens.

### `gen_escrow`

Let's assume:

- we want to stake (i.e. self-delegate) 208 tokens,
- `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw` is our staking account
  address.

:::info

Minimum delegation amount is specified by the `staking.params.min_delegation`
consensus parameter.

To obtain its value from the genesis file, run:

```bash
cat $GENESIS_FILE | \
  python3 -c 'import sys, json; \
  print(json.dumps(json.load(sys.stdin)["staking"]["params"]["min_delegation"], indent=4))'
```

Note that this value is in base units. E.g., a value of `"10000000000"` would
correspond to 10 tokens.

:::

To achieve this we need to put 208 tokens to our own escrow account.

#### Query Our Account's Info

To query our staking account's information, use the following command:

```bash
oasis-node stake account info \
  --address unix:/path/to/node/internal.sock \
  --stake.account.address oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6
```

:::info

For a detailed explanation on querying account information, see the
[Get Info](#info) section.

:::

Before the transaction, this outputs:

```
General Account:
  Balance: ROSE 431.492490765
  Nonce:   8
Escrow Account:
  Active:
    Balance:      ROSE 11242.38481664
    Total Shares: 10000000000000
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

We can observe that:

- General account's balance is ~431 tokens.
- Account's nonce is 8.
- ~11242 tokens are actively bounded to the escrow account.
- The amount of tokens that are currently debonding is 0.

#### Generate an Escrow Transaction

Let's generate an escrow transaction of 208 tokens (i.e. 208 * 10^9 base units)
to our own escrow account and store it to `tx_escrow.json`:

```bash
oasis-node stake account gen_escrow \
  "${TX_FLAGS[@]}" \
  --stake.amount 208000000000 \
  --stake.escrow.account oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6 \
  --transaction.file tx_escrow.json \
  --transaction.nonce 8 \
  --transaction.fee.gas 1000 \
  --transaction.fee.amount 2000
```

This will output a preview of the generated transaction:

```
You are about to sign the following transaction:
  Nonce:  8
  Fee:
    Amount: ROSE 0.000002
    Gas limit: 1000
    (gas price: ROSE 0.000000002 per gas unit)
  Method: staking.AddEscrow
  Body:
    Account: oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6
    Amount:  ROSE 208.0
Other info:
  Genesis document's hash: 976c302f696e417bd861b599e79261244f4391f3887a488212ee122ca7bbf0a8
```

and ask you for confirmation.

#### Submit the Transaction

To submit the generated transaction, we need to copy `tx_escrow.json` to the
online Oasis node (i.e. the `server`) and submit it from there:

```bash
oasis-node consensus submit_tx \
  --address unix:/path/to/node/internal.sock \
  --transaction.file tx_escrow.json
```

#### Query Our Account's Info Again

Let's check our account's info again:

```
General Account:
  Balance: ROSE 223.492486765
  Nonce:   9
Escrow Account:
  Active:
    Balance:      ROSE 11450.38481664
    Total Shares: 10185014125910
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

We can observe that:

- Our general account's balance decreased by 208.000002 tokens. The 0.000002
  token corresponds to the fee that we specified we will pay for this transaction.
- Our account's nonce increased to 9.
- Our escrow account's active balance increased by 208 tokens.
- The total number of shares in our escrow account's active part increased from
  10,000,000,000,000 to 10,185,014,125,910.

#### Computation of Shares

When a delegator delegates some amount of tokens to a staking account, the
delegator receives the number of shares proportional to the current
**share price** (in tokens) calculated from the total number of tokens delegated
to a staking account so far and the number of shares issued so far:

```
shares_per_token = account_issued_shares / account_delegated_tokens
```

In our case, the current share price (i.e. `shares_per_token`) is
10,000,000,000,000 / 11242.384816640 which is 889,490,989.9542729 shares per
token.

For 208 tokens, the amount of newly issued shares is thus
208 * 889,490,989.9542729 which is 185,014,125,910.48877 shares
(rounded to 185,014,125,910 shares).

Hence, the escrow account's total number of shares increased by 185,014,125,910
shares.

### `gen_reclaim_escrow`

When we want to reclaim escrowed tokens, we can't do that directly. Instead, we
need to specify the number of shares we want to reclaim from an escrow account.

Let's assume:

- we want to reclaim 357 billion shares from our escrow account,
- `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw`is our staking account address.

#### Query Our Account's Info

To query our staking account's information, use the following command:

```bash
oasis-node stake account info \
  --address unix:/path/to/node/internal.sock \
  --stake.account.address oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6
```

:::info

For a detailed explanation on querying account information, see the
[Get Info](#info) section.

:::

Before the transaction, this outputs:

```
General Account:
  Balance: ROSE 223.492486765
  Nonce:   9
Escrow Account:
  Active:
    Balance:      ROSE 11450.38481664
    Total Shares: 10185014125910
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  ...
```

We can observe that:

- General account's balance is ~223 tokens.
- Account's nonce is 9.
- ~11450 tokens are actively bounded to the escrow account.
- The amount of tokens that are currently debonding is 0.

#### Generate a Reclaim Escrow Transaction

Let's generate a reclaim escrow transaction of 357 billion shares from our own
escrow account and store it to `tx_reclaim.json`:

```bash
oasis-node stake account gen_reclaim_escrow \
  "${TX_FLAGS[@]}" \
  --stake.shares 357000000000 \
  --stake.escrow.account oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6 \
  --transaction.file tx_reclaim.json \
  --transaction.nonce 9 \
  --transaction.fee.gas 1000 \
  --transaction.fee.amount 2000
```

This will output a preview of the generated transaction:

```
You are about to sign the following transaction:
  Nonce:  9
  Fee:
    Amount: ROSE 0.000002
    Gas limit: 1000
    (gas price: ROSE 0.000000002 per gas unit)
  Method: staking.ReclaimEscrow
  Body:
    Account: oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6
    Shares:  357000000000
Other info:
  Genesis document's hash: 976c302f696e417bd861b599e79261244f4391f3887a488212ee122ca7bbf0a8
```

and ask you for confirmation.

#### Submit the Transaction

To submit the generated transaction, we need to copy `tx_reclaim.json` to the
online Oasis node (i.e. the `server`) and submit it from there:

```bash
oasis-node consensus submit_tx \
  --address unix:/path/to/node/internal.sock \
  --transaction.file tx_reclaim.json
```

#### Query Our Account's Info Again

Let's check our account's info again:

```
General Account:
  Balance: ROSE 223.492486765
  Nonce:   10
Escrow Account:
  Active:
    Balance:      ROSE 11049.031678686
    Total Shares: 9828014125910
  Debonding:
    Balance:      ROSE 401.353137954
    Total Shares: 401353137954
  ...
```

We can observe that:

- Our general account's balance decreased by 0.000002 token. This corresponds to
  the fee that we specified we will pay for this transaction.
- Our account's nonce increased to 10.
- Our escrow account's active number of shares decreased by 357 billion shares
  to 9,828,014,125,910.
- Our escrow account's active balance decreased by 401.353137954 tokens and
  is now 11049.031678686 tokens.
- Our escrow account's debonding balance increased to 401.353137954 tokens
  and its number of shares to the same amount.

#### Computation of Reclaimed Tokens

When a delegator wants to reclaim a certain number of escrowed tokens, the
**token price** (in shares) must be calculated based on the escrow account's
current active balance and the number of issued shares:

```
tokens_per_share = account_delegated_tokens / account_issued_shares
```

In our case, the current token price (i.e. `tokens_per_share`) is
11450.384816640 / 10,185,014,125,910 which is 1.124238481664054 * 10^-9 token
per share.

For 357 billion shares, the amount of tokens that will be reclaimed is thu
357 * 10^9 * 1.124238481664054 * 10^-9 which is 401.35313795406726 tokens
(rounded to 401.353137954 tokens).

Hence, the escrow account's active balance decreased by 401.353137954 tokens and
the debonding balance increased by the same amount.

:::caution

While the number of debonding shares currently equals the number of base units
that are currently subject to debonding and hence, the amount of tokens we can
expect to reclaim after debonding period is over is a little over 401 tokens,
there is no guarantee that this stays the same until the end of the debonding
period. Any slashing (e.g. for double signing) could change shares' price.

:::

#### Debonding Period

The debonding period is specified by the `staking.params.debonding_interval`
consensus parameter and is represented as a number of epochs that need to pass.

To obtain its value from the genesis file, run:

```bash
cat $GENESIS_FILE | \
  python3 -c 'import sys, json; \
  print(json.load(sys.stdin)["staking"]["params"]["debonding_interval"])'
```

For our example network, this returns:

```
10
```

After the debonding period has passed, the network will automatically move an
escrow account's debonding balance into the general account.

### `gen_cast_vote`

#### Listing Active Proposals

In order to list all active governance proposals, you can use the following
command:

```bash
oasis-node governance list_proposals --address unix:/path/to/node/internal.sock
```

In case there are currently any active proposals this should return a list of
them similar to the following:

```javascript
[{
    "id":1,
    "submitter":"oasis1qrs2dl6nz6fcxxr3tq37laxlz6hxk6kuscnr6rxj",
    "state":"active",
    "deposit":"10000000000000",
    "content":{
        "upgrade":{
            "v":1,
            "handler":"1304_testnet_upgrade",
            "target":{
                "runtime_host_protocol":{"major":2},
                "runtime_committee_protocol":{"major":2},
                "consensus_protocol":{"major":4}
            },
            "epoch":5662
        }
    },
    "created_at":5633,
    "closes_at":5645
}]
```

#### View Votes for a Proposal

To view votes for a given proposal, you can use the following command:

```bash
oasis-node governance proposal_votes \
  --address unix:/path/to/node/internal.sock \
  --proposal.id <PROPOSAL-ID>
```

replacing `<PROPOSAL-ID>` with the id of the proposal you want see.

It should return a list of cast votes for the chosen proposal similar to the
following:

```bash
[
  {
    "voter": "oasis1qq2vzcvxn0js5unsch5me2xz4kr43vcasv0d5eq4",
    "vote": "yes"
  },
  {
    "voter": "oasis1qqv25adrld8jjquzxzg769689lgf9jxvwgjs8tha",
    "vote": "yes"
  },
  {
    "voter": "oasis1qz2tg4hsatlxfaf8yut9gxgv8990ujaz4sldgmzx",
    "vote": "yes"
  },
  {
    "voter": "oasis1qz424yg28jqmgfq3xvly6ky64jqnmlylfc27d7cp",
    "vote": "no"
  },
  {
    "voter": "oasis1qr37y56g92chzvsew54kj7gu47cxyly7jytt5rm0",
    "vote": "yes"
  }
]
```

#### Voting for a Proposal

:::info

At this time only entities which have active validator nodes scheduled in the
validator set are eligible to vote for governance proposals.

:::

If you want to vote for an active proposal, you can use the following command to
generate a suitable transaction:

```bash
oasis-node governance gen_cast_vote \
  "${TX_FLAGS[@]}" \
  --vote.proposal.id 1 \
  --vote yes \
  --transaction.file tx_cast_vote.json \
  --transaction.nonce 1 \
  --transaction.fee.gas 2000 \
  --transaction.fee.amount 2000
```

This will output a preview of the generated transaction:

```bash
You are about to sign the following transaction:
  Method: governance.CastVote
  Body:
    Proposal ID: 1
    Vote:        yes
  Nonce:  1
  Fee:
    Amount: 0.000002 ROSE
    Gas limit: 2000
    (gas price: 0.000000001 ROSE per gas unit)
Other info:
  Genesis document's hash: 9ce956ef5999024e148f0c21f1e8a05ab4fc98a44c4696b289770705aeb1dd77
```

and ask you for confirmation.

#### Submit the Transaction

To submit the generated transaction, we need to copy `tx_cast_vote.json` to the
online Oasis node (i.e. the `server`) and submit it from there:

```bash
oasis-node consensus submit_tx \
  --address unix:/path/to/node/internal.sock \
  --transaction.file tx_cast_vote.json
```

### `gen_amend_commission_schedule`

We can configure our account to take a commission on staking rewards given to
our node(s). The **commission rate** must be within **commission rate bounds**,
which we can also configure.

Let's assume:

- we want to change our commission rate bounds to allow us to set any rate
  between 0% - 25%, and
- change our commission rate to 10%,
- `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6`is our staking account
  address.

We're not allowed to change the commission bounds too close in near future, so
we'd have to make changes a number of epochs in the future.

#### Commission Schedule Rules

The commission schedule rules are specified by the
`staking.params.commission_schedule_rules` consensus parameter.

To obtain its value from the genesis file, run:

```bash
cat $GENESIS_FILE | \
  python3 -c 'import sys, json; \
  rules = json.load(sys.stdin)["staking"]["params"]["commission_schedule_rules"]; \
  print(json.dumps(rules, indent=4))'
```

For our example network this returns:

```javascript
{
    "rate_change_interval": 1,
    "rate_bound_lead": 336,
    "max_rate_steps": 10,
    "max_bound_steps": 10
}
```

This means that we must submit a commission rate bound at least 336 epochs in
advance (`rate_bound_lead`) and that we can change a commission rate on every
epoch (`rate_change_interval`).

The `max_rate_steps` and `max_bound_steps` determine the maximum number of
commission rate steps and rate bound steps, respectively.

#### Query Our Account's Info

To query our staking account's information, use the following command:

```bash
oasis-node stake account info \
  --address unix:/path/to/node/internal.sock \
  --stake.account.address oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6
```

:::info

For a detailed explanation on querying account information, see the
[Show account](#show) section.

:::

Before the transaction, this outputs:

```javascript
General Account:
  ...
  Nonce:   10
Escrow Account:
  ...
  Commission Schedule:
    Rates: (none)
    Rate Bounds: (none)
  ...
```

We can observe that:

-Account's nonce is 10.
-No commissions rates or bounds are currently set.

#### Generate an Amend Commission Schedule Transaction

In this example, we'll set the bounds to start on epoch 1500. An account's
default bounds are 0% maximum, so we have to wait until our new bounds go into
effect to raise our rate to 10%. Because of that, we'll specify that our rate
also starts on epoch 1500.

Let's generate an amend commission schedule transaction for this example and
store it to `tx_amend_commission_schedule.json`:

```bash
oasis-node stake account gen_amend_commission_schedule \
  "${TX_FLAGS[@]}" \
  --stake.commission_schedule.bounds 1500/0/25000 \
  --stake.commission_schedule.rates 1500/10000 \
  --transaction.file tx_amend_commission_schedule.json \
  --transaction.nonce 10 \
  --transaction.fee.gas 1000 \
  --transaction.fee.amount 2000
```

:::info

Rates and minimum/maximum rates are in units of 1/100,000, so `0`, `50000`, and
`100000` come out to 0%, 50%, and 100%, respectively.

:::

This will output a preview of the generated transaction:

```javascript
You are about to sign the following transaction:
  Nonce:  10
  Fee:
    Amount: ROSE 0.000002
    Gas limit: 1000
    (gas price: ROSE 0.000000002 per gas unit)
  Method: staking.AmendCommissionSchedule
  Body:
    Amendment:
      Rates:
        (1) start: epoch 1500
            rate:  10.0%
      Rate Bounds:
        (1) start:        epoch 1500
            minimum rate: 0.0%
            maximum rate: 25.0%
Other info:
  Genesis document's hash: 976c302f696e417bd861b599e79261244f4391f3887a488212ee122ca7bbf0a8
```

and ask you for confirmation.

#### Submit the Transaction

To submit the generated transaction, we need to copy
`tx_amend_commission_schedule.json` to the online Oasis node (i.e. the `server`)
and submit it from there:

```bash
oasis-node consensus submit_tx \
  --address unix:/path/to/node/internal.sock \
  --transaction.file tx_amend_commission_schedule.json
```

#### Query Our Account's Info Again

Let's check our account's info again:

```javascript
General Account:
  ...
  Nonce:   11
Escrow Account:
  ...
  Commission Schedule:
    Rates:
      (1) start: epoch 1500
          rate:  10.0%
    Rate Bounds:
      (1) start:        epoch 1500
          minimum rate: 0.0%
          maximum rate: 25.0%
  ...
```

We can observe that:

* Our account's nonce increased to 11.
* We set the commission rate of 10.0% to start on epoch 1500.
* We set the commission rate bounds of 0% - 25% to also start on epoch 1500.

:::info

For more information on how commissions work in general, see the [Commission]
explanation in the _Use Your Tokens_ docs.

:::

[Commission]: https://github.com/oasisprotocol/docs/blob/main/docs/general/manage-tokens/terminology.md#commission

#### Setting a More Complex Commission Schedule

It is also possible to set multiple commission rate steps and rate bound steps
by passing the `--stake.commission_schedule.rates` and
`--stake.commission_schedule.bounds` CLI flags multiple times.

For example, setting multiple commission rate steps and rate bound steps (for
the same account as in the previous example) as follows:

```
oasis-node stake account gen_amend_commission_schedule \
  "${TX_FLAGS[@]}" \
  --stake.commission_schedule.bounds 2000/10000/30000 \
  --stake.commission_schedule.bounds 3000/20000/40000 \
  --stake.commission_schedule.rates 2000/15000 \
  --stake.commission_schedule.rates 2200/20000 \
  --stake.commission_schedule.rates 2500/25000 \
  --stake.commission_schedule.rates 2800/30000 \
  --stake.commission_schedule.rates 3000/35000 \
  --transaction.file tx_amend_commission_schedule.json \
  --transaction.nonce 11 \
  --transaction.fee.gas 1000 \
  --transaction.fee.amount 2000
```

would result in the following commission schedule being printed out in our
account's info:

```
...
Escrow Account:
  ...
  Commission Schedule:
    Rates:
      (1) start: epoch 1500
          rate:  10.0%
      (2) start: epoch 2000
          rate:  15.0%
      (3) start: epoch 2200
          rate:  20.0%
      (4) start: epoch 2500
          rate:  25.0%
      (5) start: epoch 2800
          rate:  30.0%
      (6) start: epoch 3000
          rate:  35.0%
    Rate Bounds:
      (1) start:        epoch 1500
          minimum rate: 0.0%
          maximum rate: 25.0%
      (2) start:        epoch 2000
          minimum rate: 10.0%
          maximum rate: 30.0%
      (3) start:        epoch 3000
          minimum rate: 20.0%
          maximum rate: 40.0%
  ...
```

:::info

To troubleshoot an amendment that's rejected, consult our
[compendium of 23 common ways for a commission schedule amendment to fail](https://github.com/oasisprotocol/oasis-core/blob/0dee03d75b3e8cfb36293fbf8ecaaec6f45dd3a5/go/staking/api/commission_test.go#L61-L610).

:::
