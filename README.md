# Oasis Core

[![Build status](https://badge.buildkite.com/15a8faccee0d5b5ab1af7e75eb6f9daf2d493c543fbc67dce5.svg?branch=master)](https://buildkite.com/oasislabs/oasis-core-ci)
[![Coverage Status](https://coveralls.io/repos/github/oasislabs/oasis-core/badge.svg?t=HsLWgi)](https://coveralls.io/github/oasislabs/oasis-core) Rust
[![codecov](https://codecov.io/gh/oasislabs/oasis-core/branch/master/graph/badge.svg?token=DqjRsufMqf)](https://codecov.io/gh/oasislabs/oasis-core) Go
[![GoDoc](https://godoc.org/github.com/oasislabs/oasis-core?status.svg)](https://godoc.org/github.com/oasislabs/oasis-core)

## Note

* **Oasis Core is in active development so all APIs, protocols and data structures
  are subject to change.**
* **The code has not yet been fully audited. For security issues and other
  security-related topics, see [Security](#security).**

## Contributing

See our [Contributing Guidelines](CONTRIBUTING.md).

## Security

Read our [Security](SECURITY.md) document.

## Developing and building the system

Prerequisites:

* Linux (if you are not on Linux, you will need to either set up a VM with the
  proper environment or, if Docker is available for your platform, use the
  provided Docker image which does this for you, [see below](
  #using-the-development-docker-image)).

* System packages:
  * [Bubblewrap](https://github.com/projectatomic/bubblewrap) (at least version
    0.3.3).
  * [GCC](http://gcc.gnu.org/) (including C++ subpackage).
  * [Protobuf](https://github.com/protocolbuffers/protobuf) compiler.
  * [CMake](https://cmake.org/).
  * [OpenSSL](https://www.openssl.org/) development package.
  * [libseccomp](https://github.com/seccomp/libseccomp) development package.

  On Fedora 29+, you can install all the above with:
  ```
  sudo dnf install bubblewrap gcc gcc-c++ protobuf-compiler cmake openssl-devel libseccomp-devel
  ```
  On Ubuntu 18.10+, you can install all the above with:
  ```
  sudo apt install bubblewrap gcc g++ protobuf-compiler cmake libssl-dev libseccomp-dev
  ```

* [Go](https://golang.org) (at least version 1.13).

  If your distribution provides a new-enough version of Go, just use that.

  Otherwise:
  * install the Go version provided by your distribution,
  * [ensure `$GOPATH/bin` is in your `PATH`](
    https://tip.golang.org/doc/code.html#GOPATH),
  * [install the desired version of Go](
    https://golang.org/doc/install#extra_versions), e.g. 1.13, with:
    ```
    go get golang.org/dl/go1.13
    go1.13 download
    ```
  * instruct the build system to use this particular version of Go by setting the
    `OASIS_GO` environment variable in your `~/.bashrc`:
    ```
    export OASIS_GO=go1.13
    ```

* [protoc-gen-go](https://github.com/golang/protobuf).

  Install it with:
  ```
  go get github.com/golang/protobuf/protoc-gen-go
  ```

  _NOTE: If you use a particular version of Go, i.e. the one set in
  `OASIS_GO`, then install it with:_
  ```
  $OASIS_GO get github.com/golang/protobuf/protoc-gen-go
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

Oasis development environment with all the dependencies preinstalled is available
in the `oasislabs/development:0.3.0` image. To run a container do something like the
following in the top-level directory:
```
docker run -t -i \
  --name oasis-core \
  --security-opt apparmor:unconfined \
  --security-opt seccomp=unconfined \
  -v $(pwd):/code \
  -w /code \
  oasislabs/development:0.3.0 \
  bash
```

All the following commands can then be used from inside the container. See the
Docker documentation for detailed instructions on working with Docker
containers.

## Unsafe non-SGX environment: Building and Running an Oasis node

To build everything required for running an Oasis node locally, simply execute
in the top-level directory:
```
export OASIS_UNSAFE_SKIP_AVR_VERIFY="1"
export OASIS_UNSAFE_SKIP_KM_POLICY="1"
make
```

This will build all the required parts (build tools, Oasis node, runtime
libraries, runtime loader, key manager and test runtimes). The AVR and KM flags
are supported on production SGX systems only and these features must be disabled
in our environment.

Next we specify how to run a simple network for development purposes. To start a
simple Oasis network as defined by [the default network fixture](go/oasis-net-runner/fixtures/default.go)
running the `simple-keyvalue` test runtime, do:
```
./go/oasis-net-runner/oasis-net-runner \
  --net.node.binary go/oasis-node/oasis-node \
  --net.runtime.binary target/debug/simple-keyvalue \
  --net.runtime.loader target/debug/oasis-core-runtime-loader \
  --net.keymanager.binary target/debug/oasis-core-keymanager-runtime
```

Wait for the network to start, there should be messages about nodes being started
and at the end the following message should appear:
```
level=info module=oasis/net-runner caller=oasis.go:319 ts=2019-10-03T10:47:30.776566482Z msg="network started"
level=info module=net-runner caller=root.go:145 ts=2019-10-03T10:47:30.77662061Z msg="client node socket available" path=/tmp/oasis-net-runner530668299/net-runner/network/client-0/internal.sock
```

The `simple-keyvalue` runtime implements a key-value hash map in the enclave
and supports reading, writing, and fetching string values associated with the
given key. To learn how to create your own runtime, see the sources of the
example [here](tests/runtimes/simple-keyvalue).

Finally, to test Oasis node, we will run a test client written specifically
for the `simple-keyvalue` runtime. The client sends a few keys with associated
values and fetches them back over RPC defined in the runtime's API. Execute the
client as follows (substituting the socket path from your log output) in a different
terminal:
```
./target/debug/simple-keyvalue-client \
  --runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
  --node-address unix:/tmp/oasis-net-runner530668299/net-runner/network/client-0/internal.sock
```

By default, Oasis node is configured with a 30-second epoch, so you may
initially need to wait for the first epoch to pass before the test client will
make any progress. For more information on writing your own client, see the
`simple-keyvalue` client sources [here](tests/clients/simple-keyvalue).

## SGX environment: Building and Running an Oasis node

Compilation procedure under SGX environment is similiar to the non-SGX with
slightly different environmental variables set:
```
export OASIS_UNSAFE_SKIP_AVR_VERIFY="1"
export OASIS_UNSAFE_KM_POLICY_KEYS="1"
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES="1"
export OASIS_TEE_HARDWARE=intel-sgx
make
```

The AVR flag is there because we are running a node in a local development
environment and we will not do any attestation with Intel's remote servers. The
KM policy keys flag allows testing keys to be used while verifying the security
policy of the node. TEE hardware flag denotes the trusted execution environment
engine for running the Oasis node and the tests below.

To run an Oasis node under SGX make sure:
* Your hardware has SGX support.
* You either explicitly enabled SGX in BIOS or made a
  `sgx_cap_enable_device()` system call, if SGX is in software controlled state.
* You installed Intel's SGX driver (check that `/dev/isgx` exists).
* You have the AESM daemon running. The easiest way is to just run it in a
  Docker container by doing (this will keep the container running and it will
  be automatically started on boot):
  ```
  docker run \
    --detach \
    --restart always \
    --device /dev/isgx \
    --volume /var/run/aesmd:/var/run/aesmd \
    --name aesmd \
    fortanix/aesmd
  ```

Run `sgx-detect` (part of fortanix rust tools) to verify that everything is
configured correctly.

Finally, to run an Oasis node under SGX follow the same steps as for non-SGX,
except the `oasis-net-runner` invocation:
```
./go/oasis-net-runner/oasis-net-runner \
  --net.node.binary go/oasis-node/oasis-node \
  --net.runtime.binary target/x86_64-fortanix-unknown-sgx/debug/simple-keyvalue.sgxs \
  --net.runtime.loader target/debug/oasis-core-runtime-loader \
  --net.keymanager.binary target/x86_64-fortanix-unknown-sgx/debug/oasis-core-keymanager-runtime.sgxs
```

## Running tests and benchmarks

After you built everything, you can use the following commands to run tests.

To run all unit tests:
```
make test-unit
```

To run end-to-end tests locally:
```
make test-e2e
```

To run all tests:
```
make test
```

Do not forget to set `OASIS_TEE_HARDWARE` flag (see above), if you want to
execute tests under SGX.

## Directories

* `client`: Client library for talking with the runtimes.
* `docker`: Docker environment definitions.
* `go`: Oasis node.
* `keymanager-client`: Client crate for the key manager.
* `keymanager-runtime`: (INSECURE) key manager implementation.
* `runtime`: The runtime library that simplifies writing SGX and non-SGX runtimes.
* `runtime-loader`: The SGX and non-SGX runtime loader process.
* `scripts`: Bash scripts for development.
* `tests`: Runtimes, clients and resources used for E2E tests.
* `tools`: Build tools.
