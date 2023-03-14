# `oasis-node` CLI

## `consensus`

### `submit_tx` #{consensus-submit-tx}

To submit the previously generated transaction stored in a JSON file, e.g.
`tx_transfer.json`, to the online Oasis node (i.e. the *server*) and submit it
from there:

```bash
oasis-node consensus submit_tx \
  --transaction.file tx_transfer.json \
  --address unix:/path/to/node/internal.sock
```

## `control`

### `status`

Run

```sh
oasis-node control status \
  --address unix:/path/to/node/internal.sock \
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

## `registry`

### `runtime`

#### `list`

To list all registered runtimes on the network, run:

```sh
oasis-node registry runtime list \
  --address unix:/path/to/node/internal.sock
```

```
4000000000000000000000000000000000000000000000008c5ea5e49b4bc9ac
000000000000000000000000000000000000000000000000f80306c9858e7279
000000000000000000000000000000000000000000000000e2eaa99fc008f87f
000000000000000000000000000000000000000000000000e199119c992377cb
```

Registry also stores detailed runtime information such as the runtime version,
trusted execution environment support, minimum staking requirements, governance
model etc. To view those, append the `-v` switch to increase verbosity:

```shell
oasis-node registry runtime list -v \
  --address unix:/path/to/node/internal.sock
```

## `stake`

### `account`

#### Gas Costs

We can obtain gas costs for different staking transactions from the genesis
file by running:

```bash
cat /path/to/genesis.json | \
  python3 -c 'import sys, json; \
  print(json.dumps(json.load(sys.stdin)["staking"]["params"]["gas_costs"], indent=4))'
```

For our network, this returns:

```javascript
{
    "add_escrow": 1000,
    "burn": 1000,
    "reclaim_escrow": 1000,
    "transfer": 1000
}
```

Hence, we will need to set the `--transaction.fee.gas` flag, i.e. the maximum
amount of gas a transaction can spend, in the following transactions to at
least 1000 **gas units**.

#### `gen_transfer`

Let's assume:

* `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6` is our staking account address,
* `oasis1qr3jc2yfhszpyy0daha2l9xjlkrxnzas0uaje4t3` is the destination's staking account address.

Where our staking account has:

* the general account's balance of ~601 tokens.
* account's nonce 7.

:::info

To convert your entity's ID to a staking account address, see the [Obtain Account Address From Entity's ID](address.md#obtain-account-address-from-entitys-id) section.

:::

Now let's generate a transfer transaction of 170 tokens, (i.e. 170 * 10^9 base
units), from our account to the chosen destination account and store it to
`tx_transfer.json`:

```sh
oasis-node stake account gen_transfer \
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

Then, [submit the transaction](#consensus-submit-tx).

Finally, let's check both accounts' info, [first ours](#stake-account-info):

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

and then the [destination's](#stake-account-info):

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

* Our general balance decreased by 170.000002 tokens. The 0.000002 token
  corresponds to the fee that we specified we will pay for this transaction.
* Our account's nonce increased to 8.
* Destination account's general balance increased by 170 tokens.

#### `gen_escrow`

Let's assume:

* we want to stake (i.e. self-delegate) 208 tokens,
* `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw` is our staking account address.

:::info

Minimum delegation amount is specified by the `staking.params.min_delegation` consensus parameter.

To obtain its value from the genesis file, run:

```bash
cat /path/to/genesis.json | \
  python3 -c 'import sys, json; \
  print(json.dumps(json.load(sys.stdin)["staking"]["params"]["min_delegation"], indent=4))'
```

Note that this value is in base units. E.g., a value of `"10000000000"` would correspond to 10 tokens.

:::

To achieve this we need to put 208 tokens to our **own escrow account**.

Let's [query our staking account's information](#stake-account-info) which
yields:

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

* General account's balance is ~431 tokens.
* Account's nonce is 8.
* ~11242 tokens are actively bounded to the escrow account.
* The amount of tokens that are currently debonding is 0.

Now, we will generate an escrow transaction of 208 tokens (i.e. 208 * 10^9 base
units) to our own escrow account and store it to `tx_escrow.json`:

```bash
oasis-node stake account gen_escrow \
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

Then, [submit the transaction](#consensus-submit-tx).

Finally, let's check [our account's info](#stake-account-info) again:

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

* Our general account's balance decreased by 208.000002 tokens. The 0.000002
  token corresponds to the fee that we specified we will pay for this
  transaction.
* Our account's nonce increased to 9.
* Our escrow account's active balance increased by 208 tokens.
* The total number of shares in our escrow account's active part increased from
  10,000,000,000,000 to 10,185,014,125,910.

##### Computation of Delegates Shares

When a delegator delegates some amount of tokens to a staking account, the
delegator receives the number of shares proportional to the current **share
price** (in tokens) calculated from the total number of tokens delegated to a
staking account so far and the number of shares issued so far:

```
shares_per_token = account_issued_shares / account_delegated_tokens
```

In our case, the current share price (i.e. `shares_per_token`) is
10,000,000,000,000 / 11242.384816640 which is 889,490,989.9542729 shares per
token.

For 208 tokens, the amount of newly issued shares is thus
208 * 889,490,989.9542729 which is 185,014,125,910.48877 shares (rounded to
185,014,125,910 shares).

Hence, the escrow account's total number of shares increased by 185,014,125,910
shares.

#### `gen_reclaim_escrow`

When we want to reclaim escrowed tokens, we can't do that directly. Instead, we need to specify the number of shares we want to reclaim from an escrow account.

Let's assume:

* we want to reclaim 357 billion shares from our escrow account,
* `oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw`is our staking account address.

Let's [query our staking account's information](#stake-account-info) which
yields:

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

* General account's balance is ~223 tokens.
* Account's nonce is 9.
* ~11450 tokens are actively bounded to the escrow account.
* The amount of tokens that are currently debonding is 0.

Let's generate a reclaim escrow transaction of 357 billion shares from our own
`oasis1qr6swa6gsp2ukfjcdmka8wrkrwz294t7ev39nrw6` escrow account and store it to
`tx_reclaim.json`:

```bash
oasis-node stake account gen_reclaim_escrow \
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

Then, [submit the transaction](#consensus-submit-tx).

Finally, let's check [our account's info](#stake-account-info) again:

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

* Our general account's balance decreased by 0.000002 token. This corresponds
  to the fee that we specified we will pay for this transaction.
* Our account's nonce increased to 10.
* Our escrow account's active number of shares decreased by 357 billion shares
  to 9,828,014,125,910.
* Our escrow account's active balance decreased by 401.353137954 tokens and
  is now 11049.031678686 tokens.
* Our escrow account's debonding balance increased to 401.353137954 tokens
  and its number of shares to the same amount.

##### Computation of Reclaimed Tokens

When a delegator wants to reclaim a certain number of escrowed tokens, the
**token price** (in shares) must be calculated based on the escrow account's
current active balance and the number of issued shares:

```
tokens_per_share = account_delegated_tokens / account_issued_shares
```

In our case, the current token price (i.e. `tokens_per_share`) is
11450.384816640 / 10,185,014,125,910 which is 1.124238481664054 * 10^-9 token
per share.

For 357 billion shares, the amount of tokens that will be reclaimed is thus
357 * 10^9 * 1.124238481664054 * 10^-9 which is 401.35313795406726 tokens
(rounded to 401.353137954 tokens).

Hence, the escrow account's active balance decreased by 401.353137954 tokens
and the debonding balance increased by the same amount.

:::caution

While the number of debonding shares currently equals the number of base units
that are currently subject to debonding and hence, the amount of tokens we can
expect to reclaim after debonding period is over is a little over 401 tokens,
there is no guarantee that this stays the same until the end of the debonding
period. Any slashing (e.g. for double signing) could change shares' price.

:::

##### Debonding Period

The debonding period is specified by the `staking.params.debonding_interval`
consensus parameter and is represented as a number of epochs that need to pass.

To obtain its value from the genesis file, run:

```bash
cat /path/to/genesis.json | \
  python3 -c 'import sys, json; \
  print(json.load(sys.stdin)["staking"]["params"]["debonding_interval"])'
```

For our example network, this returns:

```
10
```

After the debonding period has passed, the network will automatically move an
escrow account's debonding balance into the general account.

#### `gen_amend_commission_schedule`

See [Amend Commission Schedule].

[Amend Commission Schedule]: https://github.com/oasisprotocol/docs/blob/main/docs/node/run-your-node/validator-node/amend-commission-schedule.md

#### `info` #{stake-account-info}

To get more information about a particular staking account, e.g. `oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx`, run:

```sh
oasis-node stake account info \
  --stake.account.address oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx \
  --address unix:/path/to/node/internal.sock
```

This will output all staking information about this particular account, e.g.:

```
General Account:
  Balance: ROSE 376.594833237
  Nonce:   0
Escrow Account:
  Active:
    Balance:      ROSE 10528.684187046
    Total Shares: 10000000000000
  Debonding:
    Balance:      ROSE 0.0
    Total Shares: 0
  Commission Schedule:
    Rates: (none)
    Rate Bounds: (none)
  Stake Accumulator:
    Claims:
      - Name: registry.RegisterEntity
        Staking Thresholds:
          - Global: entity
      - Name: registry.RegisterNode.9Epy5pYPGa91IJlJ8Ivb5iby+2ii8APXdfQoMZDEIDc=
        Staking Thresholds:
          - Global: node-validator
```

##### General Account

We can observe that:

* General account's **balance**, the amount of tokens that are available to the
  account owner, is \~377 tokens.
* General account's **nonce**, the incremental number that must be unique for
  each account's transaction, is 0. That means there haven't been any
  transactions made with this account as the source. Therefore, the next
  transaction should have nonce equal to 0.

##### Escrow Account

We can observe that:

* The amount of tokens that are **actively bounded** to the escrow account is
  \~10529 tokens.
* The total number of **shares** for the tokens actively bounded to the escrow
  account is 10 trillion.
* The amount of tokens that are currently **debonding** is 0.
* The total number of **shares** for the tokens that are currently debonding is
  

###### Commission Schedule

An entity can also charge commission for tokens that are delegated to it. It
would defined the commission schedule **rate steps** and the commission
schedule **rate bound steps**. For more details, see the
[Amend Commission Schedule] documentation.

###### Stake Accumulator

Each escrow account also has a corresponding stake accumulator. It stores
**stake claims** for an escrow account and ensures all claims are satisfied
at any given point. Adding a new claim is only possible if all of the existing
claims plus the new claim can be satisfied.

We can observe that the stake accumulator currently has two claims:

* The `registry.RegisterEntity` claim is for registering an entity.

  It needs to satisfy the global threshold for registering an entity (`entity`)
  which is defined by the staking consensus parameters.

  To see the value of the `entity` global staking threshold, run the
  `oasis-node stake info` command as described in
  [Common Staking Info](#stake-info).

* The `registry.RegisterNode.9Epy5pYPGa91IJlJ8Ivb5iby+2ii8APXdfQoMZDEIDc=`
  claim is for registering the node with ID
  `9Epy5pYPGa91IJlJ8Ivb5iby+2ii8APXdfQoMZDEIDc=`.

  It needs to satisfy the global staking threshold for registering a validator
  node (`node-validator`) which is defined by the staking consensus parameters.

  To see the value of the `node-validator` global staking threshold, run the
  `oasis-node stake info` command as described in
  [Common Staking Info](#stake-info).

  In addition to the global thresholds, each runtime the node is registering
  for may define their own thresholds. In case the node is registering for
  multiple runtimes, it needs to satisfy the sum of thresholds of all the
  runtimes it is registering for.

  For more details, see the [registering a node] document.

[registering a node]: ../consensus/services/registry.md#register-node

#### `nonce`

To get the current nonce of a particular staking account, e.g.
`oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx`, run:

```bash
oasis-node stake account nonce \
  --stake.account.address oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx \
  --address unix:/path/to/node/internal.sock
```

##### Get Your Entity's Nonce

:::info

This example assumes you have the [jq](https://stedolan.github.io/jq/)
tool installed on your system.

:::

If you want to get your entity's nonce, you can use the following combination
of commands:

```bash
ENTITY_DIR=<PATH-TO-YOUR-ENTITY>
ADDRESS=$(oasis-node stake pubkey2address --public_key \
  $(cat $ENTITY_DIR/entity.json | jq .id -r))
NONCE=$(oasis-node stake account nonce --stake.account.address $ADDRESS -a unix:/path/to/node/internal.sock)
```

where `<PATH-TO-YOUR-ENTITY>` is the path to your entity's descriptor, e.g.
`/serverdir/node/entity/`.

### `info` #{stake-info}

To query an Oasis node for the common staking information, run:

```sh
oasis-node stake info \
  --address unix:/path/to/node/internal.sock
```

At time of writing this document, the command will output the following:

```
Token's ticker symbol: ROSE
Token's value base-10 exponent: 9
Total supply: 10000000000.0 ROSE
Common pool: 1319242295.211384785 ROSE
Last block fees: 0.0 ROSE
Governance deposits: 0.0 ROSE
Staking threshold (entity): 100.0 ROSE
Staking threshold (node-validator): 100.0 ROSE
Staking threshold (node-compute): 100.0 ROSE
Staking threshold (node-keymanager): 100.0 ROSE
Staking threshold (runtime-compute): 50000.0 ROSE
Staking threshold (runtime-keymanager): 50000.0 ROSE
```

We can see that the token's name is ROSE and that 1 token corresponds to 10^9
(i.e. one billion) base units.

Next, we can observe that the **total supply** is 10 billion tokens and that
about 1.3 billion tokens are in the **common pool**.

The **staking thresholds** for the entity and all node kinds (validator,
compute, key manager) are 100 tokens.

This means that if you want to register, e.g. an entity with a validator node,
you need to escrow (i.e. stake) at least 200 tokens.

Staking threshold for registering a **new runtime** (ParaTime) of any kind
(compute, key manager) is 50,000 tokens.

In addition, each runtime may require an **additional staking threshold** for
running a compute node. You need to query the registry in verbose mode to
obtain it:

```sh
oasis-node registry runtime list -v \
  --address unix:/path/to/node/internal.sock
```

For example, Emerald ParaTime running on the Mainnet has the following
additional staking requirements:

```
{
  "v": 3,
  "id": "000000000000000000000000000000000000000000000000e2eaa99fc008f87f",
  ...
  "staking": {
    "thresholds": {
      "node-compute": "5000000000000000"
    },
    "min_in_message_fee": "0"
  },
  ...
}
```

To register a node that is both a validator and a compute node for Emerald
ParaTime, the entity for which the node is registered would need to satisfy the following:

* Entity registration staking threshold (currently 100 tokens),
* Validator node staking threshold (currently 100 tokens),
* Compute node staking threshold (currently 100 tokens),
* Emerald-specific staking threshold (currently 5,000,000 tokens),

All together, there would need to be at least 5,000,300 tokens staked in your
entity's escrow account.

### `list`

To list all accounts with positive balance, run:

```sh
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

For more information on account's address format, see the [Terminology][terminology-address] doc.

### `pubkey2address`

To convert an entity ID (Base64 encoded), e.g. `nyjbDRKAXgUkL6CYfJP0WVA0XbF0pAGuvObZNMufgfY=`, to an [account address][terminology-address], run:

```bash
oasis-node stake pubkey2address \
  --public_key nyjbDRKAXgUkL6CYfJP0WVA0XbF0pAGuvObZNMufgfY=
```

This will output the staking account address for the given entity ID:

```
oasis1qrvsa8ukfw3p6kw2vcs0fk9t59mceqq7fyttwqgx
```

:::info

You can find your entity's ID in the `id` field of the `entity.json` file.

:::

[terminology-address]: https://github.com/oasisprotocol/docs/blob/main/docs/general/manage-tokens/terminology.md#address
