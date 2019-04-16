# Ekiden

[![Build status](https://badge.buildkite.com/c9c541df92d421106cdf041e36fafe45677c5be63d330509d1.svg?branch=master)](https://buildkite.com/oasislabs/ekiden)
[![Coverage Status](https://coveralls.io/repos/github/oasislabs/ekiden/badge.svg?t=HsLWgi)](https://coveralls.io/github/oasislabs/ekiden) Rust
[![codecov](https://codecov.io/gh/oasislabs/ekiden/branch/master/graph/badge.svg?token=DqjRsufMqf)](https://codecov.io/gh/oasislabs/ekiden) Go

## Developing and building the Ekiden system

Prerequisites:

* Linux (if you are not on Linux, you will need to either set up a VM with the
  proper environment or, if Docker is available for your platform, use the
  provided Docker image which does this for you, [see below](
  #using-the-development-docker-image)).

* System packages:
  * [Bubblewrap](https://github.com/projectatomic/bubblewrap) (at least version
    0.3.1).
  * [GCC](http://gcc.gnu.org/) (including C++ subpackage).
  * [Protobuf](https://github.com/protocolbuffers/protobuf) compiler.
  * [CMake](https://cmake.org/).
  * [OpenSSL](https://www.openssl.org/) development package.
  * [libseccomp](https://github.com/seccomp/libseccomp) development package.

  On Fedora 29, you can install all the above with:
  ```
  sudo dnf install bubblewrap gcc gcc-c++ protobuf-compiler cmake openssl-devel libseccomp-devel
  ```
  On Ubuntu 18.10, you can install all the above with:
  ```
  sudo apt install bubblewrap gcc g++ protobuf-compiler cmake libssl-dev libseccomp-dev
  ```

* [Go](https://golang.org) (at least version 1.12).

  If your distribution provides a new-enough version of Go, just use that.

  Otherwise:
  * install the Go version provided by your distribution,
  * [ensure `$GOPATH/bin` is in your `PATH`](
    https://tip.golang.org/doc/code.html#GOPATH),
  * [install the desired version of Go](
    https://golang.org/doc/install#extra_versions), e.g. 1.12.4, with:
    ```
    go get golang.org/dl/go1.12.4
    go1.12.4 download
    ```
  * instruct Ekiden to use this particular version of Go by setting the
    `EKIDEN_GO` environment variable in your `~/.bashrc`:
    ```
    export EKIDEN_GO=go1.12.4
    ```

* [protoc-gen-go](https://github.com/golang/protobuf).

  Install it with:
  ```
  go get github.com/golang/protobuf/protoc-gen-go
  ```

  _NOTE: If you use a particular version of Go, i.e. the one set in
  `EKIDEN_GO`, then install it with:_
  ```
  $EKIDEN_GO get github.com/golang/protobuf/protoc-gen-go
  ```

* [Rust](https://www.rust-lang.org) and the nightly toolchain.

  Once you have [`rustup` installed](https://www.rust-lang.org/tools/install),
  install the nightly with:
  ```
  rustup install nightly
  ```
  Then make it the default version with:
  ```
  rustup default nightly
  ```

* [Fortanix Rust SGX](https://edp.fortanix.com) target.

  Install it by running:
  ```
  rustup target add x86_64-fortanix-unknown-sgx
  ```
  Install its utilities by running:
  ```
  cargo install fortanix-sgx-tools sgxs-tools
  ```

In the following instructions, the top-level directory is the directory
where the code has been checked out.

### Using the development Docker image

If for some reason you don't want or can't install the specified prerequisites on the
host system, you can use our development Docker image. This requires that you have a
[recent version of Docker installed](https://docs.docker.com/install/).

Ekiden development environment with all the dependencies preinstalled is available
in the `oasislabs/development:0.3.0` image. To run a container do something like the
following in the top-level directory:
```
$ docker run -t -i \
  --name ekiden \
  --security-opt apparmor:unconfined \
  --security-opt seccomp=unconfined \
  -v $(pwd):/code \
  -w /code \
  oasislabs/development:0.3.0 \
  bash
```

All the following commands can then be used from inside the container. See the Docker
documentation for detailed instructions on working with Docker containers.

## Building

To build everything required for running an Ekiden node, simply execute in
the top-level directory:
```
$ make
```

This will build all the required parts (build tools, Ekiden node, runtime libraries,
runtime loader, key manager and test runtimes).

## Running an Ekiden node (non-SGX)

These instructions specify how to run a single-node "network" for development
purposes. For more complex setups, see E2E test helpers [here](.buildkite/scripts/common_e2e.sh).

First, make sure that you have built everything as described in the *Building* section
before proceeding and move to the top-level directory.

Before we can launch an Ekiden node, we need to copy over the identity keys
that are configured in the genesis file (instead of doing this, you could
also generate your own keys) and set correct permissions. Make sure that the
directory `/tmp/ekiden-single-node` does not exist.
```
# cp -R configs/single_node /tmp/ekiden-single-node
# chmod -R go-rwx /tmp/ekiden-single-node
```
The pre-configured Ekiden node stores data in `/tmp/ekiden-single-node`
regardless of the loaded runtime. In case you restart it, you may need to
remove this directory first and repeat the above steps for copying over the
identity keys. More information on the Ekiden node is available [here](go/README.md).

Second, we launch a single Ekiden node with an example `simple-keyvalue`
runtime loaded to trusted enclave as defined in `configs/single_node.yml`:
```
# ./go/ekiden/ekiden --config configs/single_node.yml
```

The `simple-keyvalue` runtime implements a key-value hash map in the enclave
and supports reading, writing, and fetching string values associated with the
given key. To learn how to create your own runtime, see the sources of the
example [here](tests/runtimes/simple-keyvalue).

Finally, to test Ekiden node, we will run a test client written specifically
for the `simple-keyvalue` runtime. The client sends a few keys with associated
values and fetches them back over RPC defined in the runtime's API. Execute the
client as follows:
```
# ./target/debug/simple-keyvalue-client \
    --runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
    --node-address unix:/tmp/ekiden-single-node/internal.sock
```

By default, Ekiden node is configured with a 30-second epoch, so you may
initially need to wait for the first epoch to pass before the test client will
make any progress. For more information on writing your own client, see the
`simple-keyvalue` client sources [here](tests/clients/simple-keyvalue).

## Running under SGX

In order to run under SGX there are some additional prerequisites:
* Your hardware needs to have SGX support.
* You need the AESM daemon running. The easiest way is to just run it in a
  Docker container by doing (this will keep the container running and it will
  be automatically started on boot):
  ```
  docker run \
    --detach
    --restart always \
    --device /dev/isgx \
    --volume /var/run/aesmd:/var/run/aesmd \
    --name aesmd \
    fortanix/aesmd
  ```

Run `sgx-detect` to verify that everything is configured correctly.

The instructions for running an Ekiden node under SGX are the same as above,
you only need to replace:
* `configs/single_node` with `configs/single_node_sgx`
* `configs/single_node.yml` with `configs/single_node_sgx.yml`
* `/tmp/ekiden-single-node` with `/tmp/ekiden-single-node-sgx`

## Running tests and benchmarks

After you have run `make` and built everything, you can use the following
commands to run tests.

To run all unit tests:
```
$ make test-unit
```

To run end-to-end tests:
```
$ make test-e2e
```

To run all tests:
```
$ make test
```

## Contributing

See our [contributing guidelines](CONTRIBUTING.md).

## Directories

- `client`: Client library for talking with the runtimes.
- `configs`: Example configurations for development and testing.
- `docker`: Docker environment definitions.
- `go`: Ekiden node.
- `keymanager-client`: Client crate for the key manager.
- `keymanager-runtime`: (INSECURE) key manager implementation.
- `runtime`: The runtime library that simplifies writing SGX and non-SGX runtimes.
- `runtime-loader`: The SGX and non-SGX runtime loader process.
- `scripts`: Bash scripts for development.
- `tests`: Runtimes, clients and resources used for E2E tests.
- `tools`: Build tools.
