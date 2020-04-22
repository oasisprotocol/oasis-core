# Oasis Core

[![Build status][buildkite-badge]][buildkite-link]
[![CI lint status][github-ci-lint-badge]][github-ci-lint-link]
[![CI reproducibility status][github-ci-repr-badge]][github-ci-repr-link]
[![Release status][github-release-badge]][github-release-link]
[![GoDoc][godoc-badge]][godoc-link]

<!-- NOTE: Markdown doesn't support tables without headers, so we need to
work around that and make the second (non-header) row also bold. -->
| Go            | [![Go coverage][codecov-badge]][codecov-link]       |
|:-------------:|:---------------------------------------------------:|
| **Rust**      | [![Rust coverage][coveralls-badge]][coveralls-link] |

<!-- markdownlint-disable line-length -->
[buildkite-badge]: https://badge.buildkite.com/15a8faccee0d5b5ab1af7e75eb6f9daf2d493c543fbc67dce5.svg?branch=master
[buildkite-link]: https://buildkite.com/oasislabs/oasis-core-ci
[github-ci-lint-badge]: https://github.com/oasislabs/oasis-core/workflows/ci-lint/badge.svg
[github-ci-lint-link]: https://github.com/oasislabs/oasis-core/actions?query=workflow:ci-lint
[github-ci-repr-badge]: https://github.com/oasislabs/oasis-core/workflows/ci-reproducibility/badge.svg
[github-ci-repr-link]: https://github.com/oasislabs/oasis-core/actions?query=workflow:ci-reproducibility
[github-release-badge]: https://github.com/oasislabs/oasis-core/workflows/release/badge.svg
[github-release-link]: https://github.com/oasislabs/oasis-core/actions?query=workflow:release
[codecov-badge]: https://codecov.io/gh/oasislabs/oasis-core/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/oasislabs/oasis-core
[coveralls-badge]: https://coveralls.io/repos/github/oasislabs/oasis-core/badge.svg
[coveralls-link]: https://coveralls.io/github/oasislabs/oasis-core
[godoc-badge]: https://godoc.org/github.com/oasislabs/oasis-core?status.svg
[godoc-link]: https://godoc.org/github.com/oasislabs/oasis-core
<!-- markdownlint-enable line-length -->

## Note

* **Oasis Core is in active development so all APIs, protocols and data
  structures are subject to change.**
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
  provided Docker image which does this for you,
  [see below](#using-the-development-docker-image)).

* System packages:
  * [Bubblewrap] (at least version 0.3.3).
  * [GCC] (including C++ subpackage).
  * [Protobuf] compiler.
  * [GNU Make].
  * [CMake].
  * [OpenSSL] development package.
  * [libseccomp] development package.

  On Fedora 29+, you can install all the above with:

  <!-- markdownlint-disable line-length -->
  ```
  sudo dnf install bubblewrap gcc gcc-c++ protobuf-compiler make cmake openssl-devel libseccomp-devel
  ```
  <!-- markdownlint-enable line-length -->

  On Ubuntu 18.10+ (18.04 LTS provides overly-old `bubblewrap`), you can install
  all the above with:

  ```
  sudo apt install bubblewrap gcc g++ protobuf-compiler make cmake libssl-dev libseccomp-dev
  ```

* [Go] (at least version 1.13.8).

  If your distribution provides a new-enough version of Go, just use that.

  Otherwise:
  * install the Go version provided by your distribution,
  * [ensure `$GOPATH/bin` is in your `PATH`](
    https://tip.golang.org/doc/code.html#GOPATH),
  * [install the desired version of Go](
    https://golang.org/doc/install#extra_versions), e.g. 1.13.8, with:

    ```
    go get golang.org/dl/go1.13.8
    go1.13.8 download
    ```

  * instruct the build system to use this particular version of Go by setting
    the `OASIS_GO` environment variable in your `~/.bashrc`:

    ```
    export OASIS_GO=go1.13.8
    ```

* [Rust].

  We follow [Rust upstream's recommendation][rust-upstream-rustup] on using
  [rustup] to install and manage Rust versions.

  _NOTE: rustup cannot be installed alongside a distribution packaged Rust
  version. You will need to remove it (if it's present) before you can start
  using rustup._

  Install it by running:

  ```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

  _NOTE: If you want to avoid directly executing a shell script fetched the
  internet, you can also [download `rustup-init` executable for your platform]
  and run it manually._

  This will run `rustup-init` which will download and install the latest stable
  version of Rust on your system.

* [Fortanix Rust EDP] utilities.

  Make sure a _nightly_ version of the Rust toolchain is installed:

  ```
  rustup install nightly
  ```

  Then install the Fortanix Rust EDP utilities by running:

  ```
  cargo +nightly install fortanix-sgx-tools sgxs-tools
  ```

  _NOTE: These utilities must be compiled with a nightly version of the Rust
  toolchain since they use the `#![feature]` macro._

* Oasis Core's Rust toolchain version with Fortanix SGX target.

  The version of the Rust toolchain we use in Oasis Core is specified in the
  [rust-toolchain] file.

  The rustup-installed versions of `cargo`, `rustc` and other tools will
  [automatically detect this file and use the appropriate version of the Rust
  toolchain][rust-toolchain-precedence] when invoked from the Oasis core git
  checkout directory.

  To install the appropriate version of the Rust toolchain, make sure you are
  in an Oasis Core git checkout directory and run:

  ```
  rustup show
  ```

  This will automatically install the appropriate Rust toolchain (if not
  present) and output something similar to:

  ```
  ...

  active toolchain
  ----------------

  nightly-2020-02-16-x86_64-unknown-linux-gnu (overridden by '/oasis-core/rust-toolchain')
  rustc 1.43.0-nightly (61d9231ff 2020-02-15)
  ```

  Then add the Fortanix SGX Rust target to this version of the Rust toolchain by
  running:

  ```
  rustup target add x86_64-fortanix-unknown-sgx
  ```

* (**OPTIONAL**) [protoc-gen-go].

  Download and install it with:

  ```
  GO111MODULE=on ${OASIS_GO:-go} get google.golang.org/protobuf/cmd/protoc-gen-go@v1.21.0
  ```

  _NOTE: If you didn't/can't add `$GOPATH/bin` to your `PATH`, you can install
  `protoc-gen-go` to `/usr/local/bin` (which is in `$PATH`) with:_

  <!-- markdownlint-disable line-length -->
  ```
  sudo GOBIN=/usr/local/bin GO111MODULE=on ${OASIS_GO:-go} install google.golang.org/protobuf/cmd/protoc-gen-go@v1.21.0
  ```
  <!-- markdownlint-enable line-length -->

  _NOTE: The repository has the most up-to-date files generated by protoc-gen-go
  committed for convenience.  Installing protoc-gen-go is only required if you
  are a developer making changes to protobuf definitions used by Go._

In the following instructions, the top-level directory is the directory
where the code has been checked out.

[Bubblewrap]: https://github.com/projectatomic/bubblewrap
[GCC]: http://gcc.gnu.org/
[Protobuf]: https://github.com/protocolbuffers/protobuf
[GNU Make]: https://www.gnu.org/software/make/
[CMake]: https://cmake.org/
[OpenSSL]: https://www.openssl.org/
[libseccomp]: https://github.com/seccomp/libseccomp
[Go]: https://golang.org
[rustup]: https://rustup.rs/
[rust-upstream-rustup]: https://www.rust-lang.org/tools/install
[download `rustup-init` executable for your platform]:
  https://github.com/rust-lang/rustup#other-installation-methods
[Rust]: https://www.rust-lang.org/
[rust-toolchain]: rust-toolchain
[rust-toolchain-precedence]:
  https://github.com/rust-lang/rustup/blob/master/README.md#override-precedence
[Fortanix Rust EDP]: https://edp.fortanix.com
[protoc-gen-go]: https://github.com/golang/protobuf

### Using the development Docker image

If for some reason you don't want or can't install the specified prerequisites
on the host system, you can use our development Docker image. This requires that
you have a [recent version of Docker installed](
https://docs.docker.com/install/).

Oasis development environment with all the dependencies preinstalled is
available in the `oasislabs/development:0.3.0` image.
To run a container, do the following in the top-level directory:

```bash
make docker-shell
```

If you are curious, this target will internally run the following command:

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
simple Oasis network as defined by [the default network fixture](
go/oasis-net-runner/fixtures/default.go) running the `simple-keyvalue` test
runtime, do:

```
./go/oasis-net-runner/oasis-net-runner \
  --net.node.binary go/oasis-node/oasis-node \
  --net.runtime.binary target/default/debug/simple-keyvalue \
  --net.runtime.loader target/default/debug/oasis-core-runtime-loader \
  --net.keymanager.binary target/default/debug/simple-keymanager
```

Wait for the network to start, there should be messages about nodes being
started and at the end the following message should appear:

<!-- markdownlint-disable line-length -->
```
level=info module=oasis/net-runner caller=oasis.go:319 ts=2019-10-03T10:47:30.776566482Z msg="network started"
level=info module=net-runner caller=root.go:145 ts=2019-10-03T10:47:30.77662061Z msg="client node socket available" path=/tmp/oasis-net-runner530668299/net-runner/network/client-0/internal.sock
```
<!-- markdownlint-enable line-length -->

The `simple-keyvalue` runtime implements a key-value hash map in the enclave
and supports reading, writing, and fetching string values associated with the
given key. To learn how to create your own runtime, see the sources of the
example [here](tests/runtimes/simple-keyvalue).

Finally, to test Oasis node, we will run a test client written specifically
for the `simple-keyvalue` runtime. The client sends a few keys with associated
values and fetches them back over RPC defined in the runtime's API. Execute the
client as follows (substituting the socket path from your log output) in a
different terminal:

```
./target/default/debug/simple-keyvalue-client \
  --runtime-id 8000000000000000000000000000000000000000000000000000000000000000 \
  --node-address unix:/tmp/oasis-net-runner530668299/net-runner/network/client-0/internal.sock
```

By default, Oasis node is configured with a 30-second epoch, so you may
initially need to wait for the first epoch to pass before the test client will
make any progress. For more information on writing your own client, see the
`simple-keyvalue` client sources [here](tests/clients/simple-keyvalue).

## SGX environment: Building and Running an Oasis node

Compilation procedure under SGX environment is similar to the non-SGX with
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

<!-- markdownlint-disable line-length -->
```
./go/oasis-net-runner/oasis-net-runner \
  --net.node.binary go/oasis-node/oasis-node \
  --net.runtime.binary target/sgx/x86_64-fortanix-unknown-sgx/debug/simple-keyvalue.sgxs \
  --net.runtime.loader target/default/debug/oasis-core-runtime-loader \
  --net.keymanager.binary target/sgx/x86_64-fortanix-unknown-sgx/debug/simple-keymanager.sgxs
```
<!-- markdownlint-enable line-length -->

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

### Troubleshooting

Check the console output for mentions of a path of the form
`/tmp/oasis-test-runnerXXXXXXXXX` (where each `X` is a digit).
That's the log directory. Start with coarsest-level debug output in
`console.log` files:

```
cat $(find /tmp/oasis-test-runnerXXXXXXXXX -name console.log) | less
```

For even more output, check the other `*.log` files.

## Directories

* `client`: Client library for talking with the runtimes.
* `docker`: Docker environment definitions.
* `go`: Oasis node.
* `keymanager-api-common`: Common keymanager code shared between client and lib.
* `keymanager-client`: Client crate for the key manager.
* `keymanager-lib`: Keymanager library crate.
* `runtime`: The runtime library that simplifies writing SGX and non-SGX
  runtimes.
* `runtime-loader`: The SGX and non-SGX runtime loader process.
* `scripts`: Bash scripts for development.
* `tests`: Runtimes, clients and resources used for E2E tests.
* `tools`: Build tools.
