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
  * [Clang] (including development package).
  * [Protobuf] compiler.
  * [GNU Make].
  * [CMake].
  * [pkg-config].
  * [OpenSSL] development package.
  * [libseccomp] development package.

  _NOTE: On Ubuntu/Debian systems, compiling [mbedtls] crate when building the
  `oasis-core-runtime` binary requires having the `gcc-multilib` package
  installed._

  On Fedora 29+, you can install all the above with:

  <!-- markdownlint-disable line-length -->
  ```
  sudo dnf install bubblewrap gcc gcc-c++ clang-devel clang protobuf-compiler make cmake openssl-devel libseccomp-devel pkg-config
  ```
  <!-- markdownlint-enable line-length -->

  On Ubuntu 18.10+ (18.04 LTS provides overly-old `bubblewrap`), you can install
  all the above with:

  <!-- markdownlint-disable line-length -->
  ```
  sudo apt install bubblewrap gcc g++ gcc-multilib libclang-dev clang protobuf-compiler make cmake libssl-dev libseccomp-dev pkg-config
  ```
  <!-- markdownlint-enable line-length -->

* [Go] (at least version 1.21.0).

  If your distribution provides a new-enough version of Go, just use that.

  Please note that if you want to compile Oasis Core v22.1.9 or earlier,
  then go >=1.19 is not supported yet; you need to use 1.18.x.

  Otherwise:
  * install the Go version provided by your distribution,
  * [ensure `$GOPATH/bin` is in your `PATH`](
    https://tip.golang.org/doc/code.html#GOPATH),
  * [install the desired version of Go](
    https://golang.org/doc/install#extra_versions), e.g. 1.21.0, with:

    ```
    go install golang.org/dl/go1.21.0@latest
    go1.21.0 download
    ```

  * instruct the build system to use this particular version of Go by setting
    the `OASIS_GO` environment variable in your `~/.bashrc`:

    ```
    export OASIS_GO=go1.21.0
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

  Install the Fortanix Rust EDP utilities by running:

  <!-- markdownlint-disable line-length -->
  ```
  cargo install fortanix-sgx-tools
  cargo install sgxs-tools
  ```
  <!-- markdownlint-enable line-length -->

* Oasis Core's Rust toolchain version with Fortanix SGX target.

  The version of the Rust toolchain we use in Oasis Core is specified in the
  [`rust-toolchain.toml`] file.

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

  nightly-2023-01-16-x86_64-unknown-linux-gnu (overridden by '/code/rust-toolchain.toml')
  rustc 1.68.0-nightly (9e75dddf6 2023-01-15)
  ```

* (**OPTIONAL**) [gofumpt] and [goimports].

  Required if you plan to change any of the Go code in order for automated code
  formatting (`make fmt`) to work.

  Download and install it with:

  ```
  ${OASIS_GO:-go} install mvdan.cc/gofumpt@v0.5.0
  ${OASIS_GO:-go} install golang.org/x/tools/cmd/goimports@v0.12.0
  ```

* (**OPTIONAL**) [golangci-lint].

  Required if you plan to change any of the Go code in order for automated code
  linting (`make lint`) to work.

  Download and install it with:

  ```
  curl -sSfL \
  https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
   | sh -s -- -b $(${OASIS_GO:-go} env GOPATH)/bin v1.54.2
  ```

* (**OPTIONAL**) [protoc-gen-go].

  Download and install it with:

  ```
  ${OASIS_GO:-go} install google.golang.org/protobuf/cmd/protoc-gen-go@v1.21.0
  ```

  _NOTE: If you didn't/can't add `$GOPATH/bin` to your `PATH`, you can install
  `protoc-gen-go` to `/usr/local/bin` (which is in `$PATH`) with:_

  <!-- markdownlint-disable line-length -->
  ```
  sudo GOBIN=/usr/local/bin ${OASIS_GO:-go} install google.golang.org/protobuf/cmd/protoc-gen-go@v1.21.0
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

* (**OPTIONAL**) [rocksdb] (version 8.8.1)

  # TODO: investigate clashing with jemalloc built above.
  Alternatively set `OASIS_NO_ROCKSDB="1"` environment variable when building
  `oasis-node` code, to build `oasis-node` without `rocksdb` support.

  See official instructions on building `rocksdb` for your system: https://github.com/facebook/rocksdb/blob/main/INSTALL.md

  Or use the following to build (non-portable) `rocksdb` on Ubuntu 22.04:
  ```
  # Install prerequsites.
  apt install libgflags-dev libsnappy-dev libbz2-dev liblz4-dev libzstd-dev
  # Build RocksDB.
  ROCKSDB_VERSION=8.8.1
  ROCKSDB_CHECKSUM=056c7e21ad8ae36b026ac3b94b9d6e0fcc60e1d937fc80330921e4181be5c36e
  pushd $(mktemp -d)
  wget -O rocksdb.tar.gz \
    https://github.com/facebook/rocksdb/archive/v${ROCKSDB_VERSION}.tar.gz
  # Ensure checksum matches.
  echo "${ROCKSDB_CHECKSUM}  rocksdb.tar.gz" | sha256sum -c
  tar -zxf rocksdb.tar.gz
  cd rocksdb-${ROCKSDB_VERSION}
  DEBUG_LEVEL=0 ROCKSDB_DISABLE_MALLOC_USABLE_SIZE=1 ROCKSDB_DISABLE_JEMALLOC=1 make -j4 shared_lib
  sudo make install-shared
  sudo ldconfig
  popd
  ```

In the following instructions, the top-level directory is the directory
where the code has been checked out.

<!-- markdownlint-disable line-length -->
[Bubblewrap]: https://github.com/projectatomic/bubblewrap
[GCC]: http://gcc.gnu.org/
[Clang]: https://clang.llvm.org/
[Protobuf]: https://github.com/protocolbuffers/protobuf
[GNU Make]: https://www.gnu.org/software/make/
[CMake]: https://cmake.org/
[pkg-config]: https://www.freedesktop.org/wiki/Software/pkg-config
[OpenSSL]: https://www.openssl.org/
[libseccomp]: https://github.com/seccomp/libseccomp
[mbedtls]: https://github.com/fortanix/rust-mbedtls
[Go]: https://golang.org
[rustup]: https://rustup.rs/
[rust-upstream-rustup]: https://www.rust-lang.org/tools/install
[download `rustup-init` executable for your platform]:
  https://github.com/rust-lang/rustup#other-installation-methods
[Rust]: https://www.rust-lang.org/
[`rust-toolchain.toml`]:
  https://github.com/oasisprotocol/oasis-core/tree/master/rust-toolchain.toml
[rust-toolchain-precedence]:
  https://github.com/rust-lang/rustup/blob/master/README.md#override-precedence
[Fortanix Rust EDP]: https://edp.fortanix.com
[gofumpt]: https://github.com/mvdan/gofumpt
[goimports]: https://pkg.go.dev/golang.org/x/tools/cmd/goimports
[golangci-lint]: https://golangci-lint.run/
[protoc-gen-go]: https://github.com/golang/protobuf
[jemalloc]: https://github.com/jemalloc/jemalloc
[BadgerDB]: https://github.com/dgraph-io/badger/
[jemalloc-hardcode-path]:
  https://github.com/dgraph-io/ristretto/blob/221ca9b2091d12e5d24aa5d7d56e49745fc175d8/z/calloc_jemalloc.go#L9-L13
<!-- markdownlint-enable line-length -->

## Using the Development Docker Image

If for some reason you don't want or can't install the specified prerequisites
on the host system, you can use our development Docker image. This requires that
you have a [recent version of Docker installed](
https://docs.docker.com/install/).

Oasis development environment with all the dependencies preinstalled is
available in the `ghcr.io/oasisprotocol/oasis-core-dev:master` image.
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
  ghcr.io/oasisprotocol/oasis-core-dev:master \
  bash
```

All the following commands can then be used from inside the container. See the
Docker documentation for detailed instructions on working with Docker
containers.
