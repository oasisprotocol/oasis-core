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

## Building

To build everything required for running an Ekiden node, simply execute:
```
# cd /code
# make
```

This will build all the required parts (build tools, Ekiden node, worker process,
key manager and test runtimes).

## Running an Ekiden node

Make sure that you have built everything as described in the *Building* section
before proceeding.

Starting directory for all commands is `/code`.
```
# cd /code
```

You need to run multiple Ekiden services, so it is recommended to run each of
these in a separate container shell, attached to the same container. The
following examples use the token runtime, but the process is the same for any
runtime.

*These instructions specify how to run a single-node "network" for development
purposes. For more complex setups see E2E test helpers in `.buildkite/scripts/common_e2e.sh`.*

To start the key manager:
```
# ./target/debug/ekiden-keymanager-node \
    --enclave target/enclave/ekiden-keymanager-trusted.so
```

To start a single worker using the test `token` runtime:
```
# ./go/ekiden/ekiden --config configs/single_node.yml
```

The node will store data in `/tmp/ekiden-node-data`, so in case you restart it
you may need to remove this directory first.

*More information on the Go node parameters is [available here](go/README.md).*

To test that the single node setup works you can use the built test client for the
`token` runtime:
```
# ./target/debug/token-client \
    --mr-enclave $(cat target/enclave/token.mrenclave) \
    --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
    --storage-backend remote
```

The single worker is configured with a 30-second epoch, so you may initially
need to wait for the first epoch to pass before the test client will make any
progress.

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
