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

# Oasis node, test runner, remote signer and runtime loader.
download_artifact oasis-node go/oasis-node 755
download_artifact oasis-node.test go/oasis-node 755
download_artifact oasis-test-runner go/oasis-test-runner 755
download_artifact oasis-test-runner.test go/oasis-test-runner 755
download_artifact oasis-remote-signer go/oasis-remote-signer 755
download_artifact oasis-core-runtime-loader target/default/debug 755
download_artifact example_signer_plugin go/oasis-test-runner/scenario/pluginsigner/example_signer_plugin 755

# Simple Key manager runtime.
download_artifact simple-keymanager.sgxs target/sgx/x86_64-fortanix-unknown-sgx/debug 755
download_artifact simple-keymanager target/default/debug 755

# Simple Key manager runtime used in keymenager upgrade test.
download_artifact simple-keymanager-upgrade.sgxs target/sgx/x86_64-fortanix-unknown-sgx/debug 755
download_artifact simple-keymanager-upgrade target/default/debug 755

# Test simple-keyvalue runtime.
download_artifact simple-keyvalue.sgxs target/sgx/x86_64-fortanix-unknown-sgx/debug 755
download_artifact simple-keyvalue target/default/debug 755
download_artifact simple-keyvalue-upgrade.sgxs target/sgx/x86_64-fortanix-unknown-sgx/debug 755
download_artifact simple-keyvalue-upgrade target/default/debug 755
