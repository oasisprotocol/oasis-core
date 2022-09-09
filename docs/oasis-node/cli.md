# `oasis-node` CLI

## `control`

### `status`

Run

```sh
oasis-node control status
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

### `pubkey2address`

Run

```sh
oasis-node stake pubkey2address --public_key <public_key>
```

to get staking account address from an entity or node public key. Example
response:

```
oasis1qqncl383h8458mr9cytatygctzwsx02n4c5f8ed7
```
