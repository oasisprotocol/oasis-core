# Ekiden

[![Build status](https://badge.buildkite.com/c9c541df92d421106cdf041e36fafe45677c5be63d330509d1.svg?branch=master)](https://buildkite.com/oasislabs/ekiden)
[![Coverage Status](https://coveralls.io/repos/github/oasislabs/ekiden/badge.svg?t=HsLWgi)](https://coveralls.io/github/oasislabs/ekiden) Rust
[![codecov](https://codecov.io/gh/oasislabs/ekiden/branch/master/graph/badge.svg?token=DqjRsufMqf)](https://codecov.io/gh/oasislabs/ekiden) Go

## Developing and building the Ekiden system

The canonical development environment is defined by our development Docker
container. This is done for two reasons: First it ensures good code hygene by
replicating the expectations of an SGX development environment. Second, it
provides the expected dependencies and tools, which are relatively complex to
replicate in a local environment.

Prerequisites:
* [setup the repository authentication](https://github.com/oasislabs/runtime-ethereum#configuring-repository-authentication),
* install Docker (tested with 1.13 and later) using your favorite package
  manager and setup your Docker hub credentials using `docker login`,
* install [Rust](https://www.rust-lang.org) and the nightly toolchain by
  `rustup install nightly`.

The Ekiden Docker setup typically needs more than 10 GB memory and at least 4
CPU cores. To enter the Ekiden Docker environment, use the Ekiden cargo
extension:
```
$ cargo +nightly install --force --path tools
```

To start the development container:
```
$ cargo ekiden shell
```

From now on, all commands are run in this container and not on your host.  The
actual prompt from the bash shell running in the container will look like
`root@xxxx:/code#`, where `xxxx` is the Docker container id; in the text below,
we will just use `#`.

The starting directory `/code/` in the Docker container is a mounted Ekiden
source folder on the host and any changes made are immediately visible to both
the host and the Docker container. Before compiling Ekiden in the container,
remember to [setup the repository authentication](https://github.com/oasislabs/runtime-ethereum#configuring-repository-authentication) inside the Docker container as well!

## Building the Go node

The Ekiden node is written in Go and lives under `go/`. For building the Go node in
the development container:
```
# cd /code
# make -C go
```

## Building a test runtime and client

For building enclaves we have our own Cargo extension which should be installed:
```
# cd /code
# cargo install --force --path tools
```

To build the token runtime:
```
# cd /code/tests/runtimes/token
# cargo ekiden build-enclave --output-identity
```

The built enclave will be stored under `target/enclave/token.so`.

To build the token runtime client:
```
# cd /code/tests/clients/token
# cargo build
```

## Building the key manager enclave

The key manager enclave handles secure storage of keys.

To build it:
```
# cd /code/key-manager/dummy/enclave
# cargo ekiden build-enclave --output-identity
```

The built enclave will be stored under `target/enclave/ekiden-keymanager-trusted.so`.


## Running an Ekiden node

Starting directory is
```
# cd /code
```

You need to run multiple Ekiden services, so it is recommended to run each of
these in a separate container shell, attached to the same container. The
following examples use the token runtime, but the process is the same for any
runtime.

To start the key manager:
```
# cargo run -p ekiden-keymanager-node --bin ekiden-keymanager-node -- \
    --enclave target/enclave/ekiden-keymanager-trusted.so \
    --storage-backend dummy
```

To start the shared dummy node:
```
# ./go/ekiden/ekiden --datadir /tmp/ekiden-dummy-data --grpc.port 42261
```

To start the compute node you first need to build the worker:
```
# cargo build
```

And then run at least two compute nodes each with its unique
`--worker-cache-dir` parameter for the token runtime, for example:
```
# cargo run -p ekiden-compute -- \
    --entity-ethereum-address 0000000000000000000000000000000000000000 \
    --storage-backend remote \
    --no-persist-identity \
    --worker-cache-dir to /tmp/worker1-cache
    --worker-path /code/target/debug/ekiden-worker
    target/enclave/token.so
```

The runtime's compute node will listen on `127.0.0.1` (loopback), TCP port
`9001` by default.

After starting the nodes, to manually advance the epoch in the shared dummy
node:
```
# ./go/ekiden/ekiden debug dummy set-epoch --epoch 1
```

More information on the Go node parameters is [available here](go/README.md).

Development notes:

* If you are developing a runtime and changing things, be sure to either use the `--no-persist-identity` flag or remove the referenced enclave identity file (e.g., `/tmp/token.identity.pb`). Otherwise the compute node will fail to start as it will be impossible to unseal the old identity. For more information about the content of enclave identity check [enclave identity documentation](docs/enclave-identity.md#state).

## Running tests and benchmarks

To run all tests:
```
# cargo test
```

To run end-to-end tests:
```
# .buildkite/scripts/test_e2e.sh
```

## Contributing

See our [contributing guidelines](CONTRIBUTING.md).

## Packages
- `common`: Common functionality like error handling
- `compute`: Ekiden compute node
- `roothash`: Ekiden root hash interface
- `core`: Core external-facing libraries (aggregates `common`, `enclave`, `rpc`, `db`, etc.)
- `db`: Database functionality for use in enclaves
- `di`: Dependency Injection for runtime selection of components
- `docker`: Docker environment definitions
- `enclave`: Enclave loader and identity attestation
- `epochtime`: Time synchronization
- `instrumentation`: Metric collection and instrumentation utilities
- `node`: Centralized "backend" for centralized implemnetations of APIs (e.g. a location to use as a pretend AWS)
- `registry`: Management of which hosts are online in the system
- `rpc`: RPC functionality for use in enclaves
- `scheduler`: Algorithms for assigning nodes to committees
- `scripts`: Bash scripts for development
- `stake`: ERC20 integration and API - economics of participation
- `storage`: Persistance and integration with DB and network file stores
- `testnet`: Scripts of deployment and Ops of the system
- `tests`: Runtimes, clients and resources used for E2E tests
- `tools`: Build tools
