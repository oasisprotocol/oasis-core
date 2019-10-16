#! /bin/bash

###############################################
# Download common E2E build artifacts and make
# sure they are in the correct directories for
# E2E tests to run, etc, etc.
###############################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh

# Oasis node, test runner and runtime loader.
download_artifact oasis-node go/oasis-node 755
download_artifact oasis-test-runner go/oasis-test-runner 755
download_artifact oasis-core-runtime-loader target/debug 755

# Key manager runtime.
download_artifact oasis-core-keymanager-runtime.sgxs target/x86_64-fortanix-unknown-sgx/debug 755
download_artifact oasis-core-keymanager-runtime target/debug 755

# Test simple-keyvalue runtime and clients.
download_artifact test-long-term-client target/debug 755
download_artifact simple-keyvalue-client target/debug 755
download_artifact simple-keyvalue-enc-client target/debug 755
download_artifact simple-keyvalue-ops-client target/debug 755

download_artifact simple-keyvalue.sgxs target/x86_64-fortanix-unknown-sgx/debug 755
download_artifact simple-keyvalue target/debug 755

# Test staking-arbitrary runtime and client.
download_artifact staking-arbitrary-client target/debug 755

download_artifact staking-arbitrary.sgxs target/x86_64-fortanix-unknown-sgx/debug 755
download_artifact staking-arbitrary target/debug 755
