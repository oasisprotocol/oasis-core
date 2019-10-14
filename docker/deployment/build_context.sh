#!/bin/bash

# Build a Docker context tarball.

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

###############
# Required args
###############
dst=$1

OASIS_UNSAFE_SKIP_AVR_VERIFY=1
export OASIS_UNSAFE_SKIP_AVR_VERIFY
OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES=1
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES

# Install oasis-core-tools
cargo install --force --path tools

# Build the worker, compute node and key manager
make -C go
cargo build -p oasis-core-runtime-loader --release

pushd keymanager-runtime
    OASIS_UNSAFE_SKIP_KM_POLICY=1 cargo build --release

    unset OASIS_UNSAFE_SKIP_KM_POLICY
    cargo build --release --target x86_64-fortanix-unknown-sgx
    cargo elf2sgxs --release
popd

tar -czf "$dst" \
    go/oasis-node/oasis-node \
    target/release/oasis-core-runtime-loader \
    target/release/oasis-core-keymanager-runtime \
    target/x86_64-fortanix-unknown-sgx/release/oasis-core-keymanager-runtime.sgxs \
    docker/deployment/Dockerfile
