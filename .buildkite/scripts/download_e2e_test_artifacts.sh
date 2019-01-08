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

# Ekiden node, worker and compute node.
download_artifact ekiden go/ekiden 755
download_artifact ekiden-worker target/debug 755
download_artifact ekiden-compute target/debug 755

# Key manager.
download_artifact ekiden-keymanager-node target/debug 755

# Key manager enclave.
download_artifact ekiden-keymanager-trusted.so target/enclave 755
download_artifact ekiden-keymanager-trusted.mrenclave target/enclave

# Test token runtime and clients.
download_artifact test-long-term-client target/debug 755
download_artifact token-client target/debug 755
download_artifact token.so target/enclave 755
download_artifact token.mrenclave target/enclave

# Test db encryption runtime and clients.
download_artifact ekiden-keymanager-test-client target/debug 755
download_artifact test-db-encryption-client target/debug 755
download_artifact test-db-encryption.so target/enclave 755
download_artifact test-db-encryption.mrenclave target/enclave
