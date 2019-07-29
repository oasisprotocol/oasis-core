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
download_artifact ekiden-test-runner go/ekiden-test-runner 755
download_artifact ekiden-runtime-loader target/debug 755

# Key manager runtime.
download_artifact ekiden-keymanager-runtime.sgxs target/x86_64-fortanix-unknown-sgx/debug 755
download_artifact ekiden-keymanager-runtime target/debug 755

# Test simple-keyvalue runtime and clients.
download_artifact test-long-term-client target/debug 755
download_artifact simple-keyvalue-client target/debug 755
download_artifact simple-keyvalue-enc-client target/debug 755
download_artifact simple-keyvalue-ops-client target/debug 755

download_artifact simple-keyvalue.sgxs target/x86_64-fortanix-unknown-sgx/debug 755
download_artifact simple-keyvalue target/debug 755
