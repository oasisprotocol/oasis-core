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
