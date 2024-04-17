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

# Randomize beginning of downloads to increase hits in CI pipeline cache
sleep $((RANDOM % 5))

# Oasis node, test runner and runtime loader.
download_artifact oasis-node go/oasis-node 755
download_artifact oasis-node.test go/oasis-node 755
download_artifact oasis-test-runner go/oasis-test-runner 755
download_artifact oasis-test-runner.test go/oasis-test-runner 755

# Runtime loader.
download_artifact oasis-core-runtime-loader target/default/release 755

# Simple key manager runtime.
download_artifact simple-keymanager.mocksgx target/default/release 755
mv target/default/release/simple-keymanager.mocksgx target/default/release/simple-keymanager
download_artifact simple-keymanager.sgxs target/sgx/x86_64-fortanix-unknown-sgx/release 755

# Test simple-keyvalue runtime.
download_artifact simple-keyvalue.mocksgx target/default/release 755
mv target/default/release/simple-keyvalue.mocksgx target/default/release/simple-keyvalue
download_artifact simple-keyvalue.sgxs target/sgx/x86_64-fortanix-unknown-sgx/release 755
