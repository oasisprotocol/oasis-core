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

These instructions specify how to run a single-node "network" for development
purposes. For more complex setups, see E2E test helpers [here](.buildkite/scripts/common_e2e.sh).

First, make sure that you have built everything as described in the *Building* section
before proceeding and move to the starting directory `/code`:
```
# cd /code
```

We will execute multiple ekiden services, so it is convenient to start a new
`ekiden shell` instance for each service.

First, we start a key manager service, which stores encryption keys in a
protected enclave:
```
# ./target/debug/ekiden-keymanager-node \
    --storage-path /tmp/ekiden-keymanager-node \
    --enclave target/enclave/ekiden-keymanager-trusted.so
```

Second, we launch a single Ekiden node with an example `simple-keyvalue`
runtime loaded to trusted enclave as defined in `configs/single_node.yml`:
```
# ./go/ekiden/ekiden --config configs/single_node.yml
```

The `simple-keyvalue` runtime implements a key-value hash map in the enclave
and supports reading, writing, and fetching string values associated with the
given key. To learn how to create your own runtime, see the sources of the
example [here](tests/runtimes/simple-keyvalue).

Ekiden node stores data in `/tmp/ekiden-node-data` regardless the loaded
runtime. In case you restart it, you may need to remove this directory first.
More information on Ekiden node is available [here](go/README.md).

Finally, to test Ekiden node, we will run a test client written specifically
for the `simple-keyvalue` runtime. The client sends a few keys with associated
values and fetches them back over RPC defined in the runtime's API. Execute the
client as follows:
```
# ./target/debug/simple-keyvalue-client \
    --mr-enclave $(cat target/enclave/simple-keyvalue.mrenclave) \
    --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
    --node-address unix:/tmp/ekiden-node-data/internal.sock
```

By default, Ekiden node is configured with a 30-second epoch, so you may
initially need to wait for the first epoch to pass before the test client will
make any progress. For more information on writing your own client, see the
`simple-keyvalue` client sources [here](tests/clients/simple-keyvalue).

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
- `instrumentation`: Metric collection and instrumentation utilities
- `node`: Centralized "backend" for centralized implemnetations of APIs (e.g. a location to use as a pretend AWS)
- `registry`: Management of which hosts are online in the system
- `rpc`: RPC functionality for use in enclaves
- `scheduler`: Algorithms for assigning nodes to committees
- `scripts`: Bash scripts for development
- `storage`: Persistance and integration with DB and network file stores
- `testnet`: Scripts of deployment and Ops of the system
- `tests`: Runtimes, clients and resources used for E2E tests
- `tools`: Build tools
