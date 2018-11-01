# Ekiden Node

## Installation

Code is compiled against Go 1.11.x.

In addition, we expect the following tools, which are present in the
development docker environment:
* [golangci-lint](https://github.com/golangci/golangci-lint)
* [protoc](https://github.com/google/protobuf)
* [protobuf](https://github.com/golang/protobuf) Version 1.1.0

You can build everything by running:
```
make
```

If you want to run individual steps, the following steps are used for compilation:
```
make generate
make build
```

To lint run:
```
make lint
```

## Sub-commands

In addition to implementing the Ekiden node, the `ekiden` command also
implements various sub-commands for the purpose of interacting with the
node, development, and debugging.

All sub-commands have online documentation that can be accessed via the
`--help` parameter, for example:
```
ekiden dummy set-epoch --help
```

### `dummy` - Control the dummy (centralized) node during tests

The `dummy` sub-command provides faclities for controlling the centralized
node during tests.

#### `dummy set-epoch` - Set the Oasis epoch

The `dummy set-epoch` sub-command allows the node's Oasis epoch to be
set to an arbitrary value, provided a compatible epochtime backend is
being used (`mock`, `tendermint_mock`).

```
ekiden dummy set-epoch -e 2600    # Set the epoch to 2600
```

#### `dummy wait-nodes` - Wait for a specific number of nodes to register

The `dummy wait-nodes` sub-command will block until the requested number
of compute worker nodes have registered.

```
ekiden dummy wait-nodes -n 5      # Wait until 5 compute nodes register
```

### `registry` - Registry backend utilities

The `registry` sub-command provides faclities for interacting with the
various registries.

#### `registry list-runtimes` - List registered runtimes

The `registry list-runtimes` sub-command will dump the runtime IDs of all
currently registered runtimes as newline deliniated hexadecimal strings.

```
ekiden registry list-runtimes
```

### `roothash` - Root hash backend utilites

The `roothash` sub-command provides facilities for interacting with the
root hash backend.

#### `roothash export` - Export the current root hash(es)

The `roothash export` sub-command will fetch the current root hash block(s)
for the requested runtime IDs and write them in a binary serialized format,
suitable for use with the main `ekiden` command's `--roothash.geneisis-blocks`
argument.

**WARNING**: The root hash block serialization format is deliberately opaque,
unstable, and unspecifed.  **Root hash blocks exported via this command are
NOT guaranteed to be compatible across different versions of the
`ekiden` command**.

```
RUNTIME_ID = 0000000000000000000000000000000000000000000000000000000000000000
ekiden roothash export $RUNTIME_ID                 # Export to stdout
ekiden roothash export $RUNTIME_ID -o roothash.bin # Export to roothash.bin
```
