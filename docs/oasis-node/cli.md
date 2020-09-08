# `oasis-node` CLI

## `control`

### `status`

Run

```sh
oasis-node control status
```

to get information like the following (example taken from a runtime compute
node):

```json
{
  "software_version": "20.10",
  "identity": {
    "node": "kO/mEZfAnnRnGqpA5JqlZLaIf+bMTIZAriivJdWSTco=",
    "p2p": "EwriyXpMKatrC1X2Z+KsDRkdu0NXWV4/25TRSa59z8o=",
    "consensus": "4AaxFrlyZwQhGmk58+Up/gDg5eY1mwJpFEE9WXulg9Q=",
    "tls": [
      "1ZWRWMA/gx0nfGH6xJNKAlYUPaGkBz2LxTe552bCO68=",
      "XGOH0m3CQVSG1J9AFxefgSWF+YP6eRnxmjM5zmj2gLs="
    ]
  },
  "consensus": {
    "consensus_version": "1.0.0",
    "backend": "tendermint",
    "features": 3,
    "node_peers": [
      "5c8272d22b3bc0ee282c9e21682b22ce6d68078c@127.0.0.1:20000"
    ],
    "latest_height": 185,
    "latest_hash": "N6dmMPB2A+n4EkCv684TAtARRGrxcobouHfq1daXoBk=",
    "latest_time": "2020-09-08T11:18:54+02:00",
    "latest_state_root": {
      "ns": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "version": 184,
      "hash": "ITfGAos0wY40Y1qmf7vr7f2jvA+cMRPswql3RqhTyDc="
    },
    "genesis_height": 1,
    "genesis_hash": "fYbBfC987n0RXS1TsicvCVViOWjBe/9gwyEW6kTev/c=",
    "is_validator": false
  },
  "runtimes": {
    "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=": {
      "descriptor": {
        "v": 1,
        "id": "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "entity_id": "TqUyj5Q+9vZtqu10yw6Zw7HEX3Ywe0JQA9vHyzY47TU=",
        "genesis": {
          "state_root": "xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno=",
          "state": null,
          "storage_receipts": null,
          "round": 0
        },
        "kind": 1,
        "tee_hardware": 0,
        "versions": {
          "version": {}
        },
        "key_manager": "wAAAAAAAAAD///////////////////////////////8=",
        "executor": {
          "group_size": 2,
          "group_backup_size": 1,
          "allowed_stragglers": 0,
          "round_timeout": 20
        },
        "txn_scheduler": {
          "algorithm": "simple",
          "batch_flush_timeout": 20000000000,
          "max_batch_size": 1,
          "max_batch_size_bytes": 16777216,
          "propose_batch_timeout": 20
        },
        "storage": {
          "group_size": 1,
          "min_write_replication": 1,
          "max_apply_write_log_entries": 100000,
          "max_apply_ops": 2,
          "checkpoint_interval": 0,
          "checkpoint_num_kept": 0,
          "checkpoint_chunk_size": 0
        },
        "admission_policy": {
          "any_node": {}
        },
        "staking": {}
      },
      "latest_round": 5,
      "latest_hash": "3chaVOZUeJwPBZNbFUh622STrvtrEVlIee7unu/S880=",
      "latest_time": 1599556729,
      "latest_state_root": {
        "ns": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "version": 5,
        "hash": "xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno="
      },
      "genesis_round": 0,
      "genesis_hash": "T4zq6ris0pGNvkgfhGmPnnDMzbMo+8rUPhfxbyAZ2tg=",
      "committee": {
        "latest_round": 5,
        "latest_height": 180,
        "last_committee_update_height": 180,
        "executor_role": "worker",
        "storage_role": "invalid",
        "is_txn_scheduler": true,
        "peers": [
          "/ip4/172.25.0.2/tcp/20015/p2p/12D3KooWQ6gDSgYBYqUfERm8BQdFtozJ5Wg6LQeLwQz1LCPPx8B4",
          "/ip4/127.0.0.1/tcp/20012/p2p/12D3KooWQEjvQjwweWxv8mH7YbsQxJaQB7VqYu1QopWvmoFSZ6Pi"
        ]
      },
      "storage": null
    }
  },
  "registration": {
    "last_registration": "2020-09-08T11:18:51+02:00",
    "descriptor": {
      "v": 1,
      "id": "kO/mEZfAnnRnGqpA5JqlZLaIf+bMTIZAriivJdWSTco=",
      "entity_id": "wmYfQjpQHaOj9SSmWL/oYx1kHnatBI9so+eH33E0qig=",
      "expiration": 8,
      "tls": {
        "pub_key": "1ZWRWMA/gx0nfGH6xJNKAlYUPaGkBz2LxTe552bCO68=",
        "next_pub_key": "XGOH0m3CQVSG1J9AFxefgSWF+YP6eRnxmjM5zmj2gLs=",
        "addresses": [
          "XGOH0m3CQVSG1J9AFxefgSWF+YP6eRnxmjM5zmj2gLs=@172.25.0.2:20008"
        ]
      },
      "p2p": {
        "id": "EwriyXpMKatrC1X2Z+KsDRkdu0NXWV4/25TRSa59z8o=",
        "addresses": [
          "172.25.0.2:20009",
          "127.0.0.1:20009"
        ]
      },
      "consensus": {
        "id": "4AaxFrlyZwQhGmk58+Up/gDg5eY1mwJpFEE9WXulg9Q=",
        "addresses": null
      },
      "runtimes": [
        {
          "id": "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          "version": {
            "minor": 3
          },
          "capabilities": {},
          "extra_info": null
        }
      ],
      "roles": 1
    }
  }
}
```

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
