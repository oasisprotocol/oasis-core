# Benchmarking on SGX hardware

1. Check out a contract. Initialize submodules.
2. Enter the contract's container using this repo's scripts/sgx-enter-hw.sh.
   This variant of the script sets flags for building for hardware SGX.
3. In container: Build ekiden, the contract, and the benchmarking programs.
   Use release mode.
4. In container: Start aesmd using this repo's scripts/start-aesmd.sh.
   This script is meant to be sourced, and it starts a background job in your current shell.

Then start the nodes and run the benchmarking program.
See [/testnet/tendermint/README.md](/testnet/tendermint/README.md) for how to use the consensus testnet.

See issue [#292](https://github.com/sunblaze-ucb/ekiden/issues/292) for a sample set of commands we used to this in our experiments.
