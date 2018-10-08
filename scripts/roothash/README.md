# Roothash import/export
This directory contains tools for migrating the latest block in a
roothash service across roothash backend implementations.

## Overview
1. `list-contracts.py` is a script for **listing** the registered
   runtimes on a registry GRPC service. It uses the `GetContracts`
   function of a registry GRPC service. It writes the runtime IDs to
   stdout in hex.
2. `export.py` is a script for **exporting** the latest blocks. It
   uses the `GetLatestBlock` function of a roothash GRPC service. It
   writes a list of (runtime ID, latest block) pairs to stdout in an
   arbitrary format.
3. The dummy node supports a command line argument for **importing**
   blocks to use as genesis blocks. It reads a list of (runtime ID,
   genesis block) pairs in the same format.

This serialized format is not especially suitable for archival,
because it's not versioned, and we don't have plans to write
migrations for it.

## Setup
These scripts need Python 2 and the dependencies listed in
`requirements.txt`.
It needs `grpc-tools` to compile the GRPC code, and you can get away
witout it at runtime.
You can install these in our development container with `make
container-deps` in this directory.
Or, you can install these with pip using `pip install -r
requirements.txt`.

Build the protocol buffers and GRPC definitions with `make` in this
directory.

## Usage
Refer to the online documentation for command line options.

```sh
./scripts/roothash/list-contracts.py --help
```

```sh
./scripts/roothash/export.py --help
```

```sh
./go/ekiden/ekiden --help
```

## Handy invocations
List contracts registered in a registry service and export those from
a registry service and a roothash service on localhost on the default
port (42261) and save to a file:

```sh
./scripts/roothash/list-contracts.py | xargs ./scripts/roothash/export.py >/tmp/ekiden-roothash.dat
```

Look at the runtimes and blocks in a file:

```sh
protoc --decode=roothash.GenesisBlocks -I roothash/api/src roothash/api/src/roothash.proto </tmp/ekiden-roothash.dat
```

Start a dummy node using blocks from a file:

```sh
./go/ekiden/ekiden (other flags) --roothash.genesis-blocks /tmp/ekiden-roothash.dat
```

## Representation of latest blocks
These programs work with runtimes' latest/genesis blocks represented
as a protocol buffers serialized `roothash.GenesisBlocks` message, as
defined in [roothash.proto](/roothash/api/src/roothash.proto).
