# Prerequisites

The following is a list of prerequisites required to start developing on Oasis
Core:

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
  * [pkg-config].
  * [OpenSSL] development package.
  * [libseccomp] development package.

  On Fedora 29+, you can install all the above with:

  <!-- markdownlint-disable line-length -->
  ```
  sudo dnf install bubblewrap gcc gcc-c++ protobuf-compiler make cmake openssl-devel libseccomp-devel pkg-config
  ```
  <!-- markdownlint-enable line-length -->

  On Ubuntu 18.10+ (18.04 LTS provides overly-old `bubblewrap`), you can install
  all the above with:

  <!-- markdownlint-disable line-length -->
  ```
  sudo apt install bubblewrap gcc g++ protobuf-compiler make cmake libssl-dev libseccomp-dev pkg-config
  ```
  <!-- markdownlint-enable line-length -->

* [Go] (at least version 1.16.3).

  If your distribution provides a new-enough version of Go, just use that.

  Otherwise:
  * install the Go version provided by your distribution,
  * [ensure `$GOPATH/bin` is in your `PATH`](
    https://tip.golang.org/doc/code.html#GOPATH),
  * [install the desired version of Go](
    https://golang.org/doc/install#extra_versions), e.g. 1.16.3, with:

    ```
    go get golang.org/dl/go1.16.3
    go1.16.3 download
    ```

  * instruct the build system to use this particular version of Go by setting
    the `OASIS_GO` environment variable in your `~/.bashrc`:

    ```
    export OASIS_GO=go1.16.3
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
  cargo +nightly install --version 0.4.0 fortanix-sgx-tools
  cargo +nightly install --version 0.8.2 sgxs-tools
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

  nightly-2021-05-20-x86_64-unknown-linux-gnu (overridden by '/code/rust-toolchain')
  rustc 1.54.0-nightly (f94942d84 2021-05-19)
  ```

  Then add the Fortanix SGX Rust target to this version of the Rust toolchain by
  running:

  ```
  rustup target add x86_64-fortanix-unknown-sgx
  ```

* (**OPTIONAL**) [gofumpt and gofumports].

  Required if you plan to change any of the Go code in order for automated code
  formatting (`make fmt`) to work.

  Download and install it with:

  ```
  export GOFUMPT_VERSION=abc0db2c416aca0f60ea33c23c76665f6e7ba0b6
  GO111MODULE=on ${OASIS_GO:-go} get mvdan.cc/gofumpt@${GOFUMPT_VERSION}
  GO111MODULE=on ${OASIS_GO:-go} get mvdan.cc/gofumpt/gofumports@${GOFUMPT_VERSION}
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

* (**OPTIONAL**) [jemalloc] (version 5.2.1, built with `'je_'` jemalloc-prefix)

  Alternatively set `OASIS_BADGER_NO_JEMALLOC="1"` environment variable when
  building `oasis-node` code, to build [BadgerDB] without `jemalloc` support.

  Download and install `jemalloc` with:

  ```
  JEMALLOC_VERSION=5.2.1
  JEMALLOC_CHECKSUM=34330e5ce276099e2e8950d9335db5a875689a4c6a56751ef3b1d8c537f887f6
  JEMALLOC_GITHUB=https://github.com/jemalloc/jemalloc/releases/download/
  pushd $(mktemp -d)
  wget \
    -O jemalloc.tar.bz2 \
    "${JEMALLOC_GITHUB}/${JEMALLOC_VERSION}/jemalloc-${JEMALLOC_VERSION}.tar.bz2"
  # Ensure checksum matches.
  echo "${JEMALLOC_CHECKSUM} jemalloc.tar.bz2" | sha256sum -c
  tar -xf jemalloc.tar.bz2
  cd jemalloc-${JEMALLOC_VERSION}
  # Ensure reproducible jemalloc build.
  # https://reproducible-builds.org/docs/build-path/
  EXTRA_CXXFLAGS=-ffile-prefix-map=$(pwd -L)=. \
    EXTRA_CFLAGS=-ffile-prefix-map=$(pwd -L)=. \
    ./configure \
      --with-jemalloc-prefix='je_' \
      --with-malloc-conf='background_thread:true,metadata_thp:auto'
  make
  sudo make install
  popd
  ```

  _NOTE: jemalloc needs to be installed to the (default) `/usr/local` prefix
  (i.e. you can't use `./configure --prefix=$HOME/.local ...`) because upstream
  authors [hardcode its path][jemalloc-hardcode-path]._

In the following instructions, the top-level directory is the directory
where the code has been checked out.

[Bubblewrap]: https://github.com/projectatomic/bubblewrap
[GCC]: http://gcc.gnu.org/
[Protobuf]: https://github.com/protocolbuffers/protobuf
[GNU Make]: https://www.gnu.org/software/make/
[CMake]: https://cmake.org/
[pkg-config]: https://www.freedesktop.org/wiki/Software/pkg-config
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
[gofumpt and gofumports]: https://github.com/mvdan/gofumpt
[protoc-gen-go]: https://github.com/golang/protobuf
[jemalloc]: https://github.com/jemalloc/jemalloc
[BadgerDB]: https://github.com/dgraph-io/badger/
<!-- markdownlint-disable line-length -->
[jemalloc-hardcode-path]:
  https://github.com/dgraph-io/ristretto/blob/221ca9b2091d12e5d24aa5d7d56e49745fc175d8/z/calloc_jemalloc.go#L9-L13
<!-- markdownlint-enable line-length -->

## Using the Development Docker Image

If for some reason you don't want or can't install the specified prerequisites
on the host system, you can use our development Docker image. This requires that
you have a [recent version of Docker installed](
https://docs.docker.com/install/).

Oasis development environment with all the dependencies preinstalled is
available in the `oasisprotocol/oasis-core-dev:master` image.
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
  oasisprotocol/oasis-core-dev:master \
  bash
```

All the following commands can then be used from inside the container. See the
Docker documentation for detailed instructions on working with Docker
containers.
