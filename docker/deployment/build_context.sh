#!/bin/bash

# Build a Docker context tarball.

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

###############
# Required args
###############
dst=$1

: ${SGX_MODE:=SIM}
export SGX_MODE
EKIDEN_UNSAFE_SKIP_AVR_VERIFY=1
export EKIDEN_UNSAFE_SKIP_AVR_VERIFY
: ${INTEL_SGX_SDK:=/opt/sgxsdk}
export INTEL_SGX_SDK

# Install ekiden-tools
cargo install --force --path tools

# Build the worker, compute node and key manager
make -C go
cargo build -p ekiden-worker --release
cargo build -p ekiden-keymanager-node --release
(cd key-manager/dummy/enclave && cargo ekiden build-enclave --output-identity --release)

tar -czf "$dst" \
    go/ekiden/ekiden \
    target/release/ekiden-worker \
    target/release/ekiden-keymanager-node \
    target/enclave/ekiden-keymanager-trusted.so \
    target/enclave/ekiden-keymanager-trusted.mrenclave \
    docker/deployment/Dockerfile
