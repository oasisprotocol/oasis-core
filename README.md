# Ekiden

[![CircleCI](https://circleci.com/gh/sunblaze-ucb/ekiden.svg?style=svg&circle-token=1e61090ac6971ca5db0514e4593d5fdeff83f6a9)](https://circleci.com/gh/sunblaze-ucb/ekiden)

## Dependencies

Here is a brief list of system dependencies currently used for development:
- [rustc](https://www.rust-lang.org/en-US/)
- [cargo](http://doc.crates.io/)
- [cargo-make](https://crates.io/crates/cargo-make)
- [xargo](https://github.com/japaric/xargo)
- [docker](https://www.docker.com/)
- [rust-sgx-sdk](https://github.com/ekiden/rust-sgx-sdk)
- [protoc](https://github.com/google/protobuf/releases)

## Checking out

The repository uses submodules so be sure to check them out by doing:
```bash
$ git submodule update --init --recursive
```

## Building

The easiest way to build SGX code is to use the provided scripts, which run a Docker
container with all the included tools. This has been tested on MacOS and Ubuntu with `SGX_MODE=SIM`.

To start the SGX development container:
```bash
$ ./scripts/sgx-enter.sh
```

Ekiden uses [`cargo-make`](https://crates.io/crates/cargo-make) as the build system. The
development Docker container already comes with `cargo-make` preinstalled.

To build everything required for running Ekiden, simply run the following in the top-level
directory:
```bash
$ cargo make
```

This should install any required dependencies and build all packages. By default SGX code is
built in simulation mode. To change this, do `export SGX_MODE=HW` (currently untested) before
running the `cargo make` command.

## Obtaining contract MRENCLAVE

In order to establish authenticated channels with Ekiden contract enclaves, the client needs
to know the enclave hash (MRENCLAVE) so it knows that it is talking with the correct contract
code.

To obtain the enclave hash, there is a utility that you can run:
```bash
$ python scripts/parse_enclave.py target/enclave/token.signed.so
```

This utility will output a lot of enclave metadata, the important part is:
```
         ...
         ENCLAVEHASH    e38ded31efe3beb062081dc9a7f9af4b785ae8fa2ce61e0bddec2b6aedb02484
         ...
```

You will need this hash when running the contract client (see below).

## Obtaining SPID and generating PKCS#12 bundle

In order to communicate with Intel Attestation Service (IAS), you need to generate a certificate
and get an SPID from Intel. For more information on that process, see the following links:
* [How to create self-signed certificates for use with Intel SGX RA](https://software.intel.com/en-us/articles/how-to-create-self-signed-certificates-for-use-with-intel-sgx-remote-attestation-using)
* [Apply for an SPID](https://software.intel.com/formfill/sgx-onboarding)

You will need to pass both SPID and the PKCS#12 bundle when starting the compute node.

## Running

The easiest way to run Ekiden is through the provided scripts,
which set up the Docker containers for you.

### Consensus node

The consensus node is built by the `cargo run` command.  To run it,

```bash
$ bash scripts/sgx-enter.sh
root@xxxx:/code# target/debug/ekiden-consensus -x
```

The `-x` flag tells the consensus node to not depend on Tendermint.

### Compute node

Currently, the 2 processes (compute and consensus) look for each other on `localhost`.
In order to attach secondary shells to an existing container, run
```bash
$ bash scripts/sgx-enter.sh
```

To run a contract on a compute node:
```bash
# optionally set the following env vars
export IAS_SPID="<IAS SPID>"
export IAS_PKCS="client.pfx"
scripts/run_contract.sh CONTRACT
```

To get a list of built contract enclaves:
```bash
$ ls ./target/enclave/*.signed.so
```

### Key manager

The key manager contract is special and must be run in a compute node listening on port `9003`
by default. Run it as you would run any other compute node, but specifying the key manager
contract and changing the port:
```bash
$ scripts/run_contract.sh ekiden-key-manager -p 9003 --disable-key-manager --consensus-host disabled
```

### Contract client

To run the token contract client:
```bash
$ scripts/run_contract.sh --client token
```

## Developing

We welcome anyone to fork and submit a pull request! Please make sure to run `rustfmt` before submitting.

```bash
$ cargo make format
```

## Packages
- `core`: Core external-facing libraries (aggregates `common`, `enclave`, `rpc`, `db`, etc.)
- `common`: Common functionality like error handling
- `enclave`: Enclave loader and identity attestation
- `rpc`: RPC functionality for use in enclaves
- `db`: Database functionality for use in enclaves
- `compute`: Ekiden compute node
- `consensus`: Ekiden consensus node
- `contracts`: Core contracts (`key-manager`, `token`)
- `tools`: Build tools
- `scripts`: Bash scripts for development
