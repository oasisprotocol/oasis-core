# `oasis-node` CLI

## `control`

### `status`

Run

```sh
oasis-node control status
```

to get information like the following:

```json
{
  "software_version": "20.8",
  "identity": {
    "node": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "p2p": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "consensus": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "tls": null
  },
  "consensus": {
    "consensus_version": "0.25.0",
    "backend": "tendermint",
    "node_peers": [
      "(redacted)@(redacted):26656",
      ...
    ],
    "latest_height": 177689,
    "latest_hash": "rvE8ueXb66PGW4DCmhS3PfjLnO2sMyZSkwXufCbsrfg=",
    "latest_time": "2020-06-30T10:48:07-07:00",
    "genesis_height": 1,
    "genesis_hash": "c5/n2FPM6VRcrP20I0igB1NFCRLUJFnAVnLw25t8u6w=",
    "is_validator": false
  },
  "registration": {
    "last_registration": "0001-01-01T00:00:00Z"
  }
}
```

(example taken from a non-validator node)

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
