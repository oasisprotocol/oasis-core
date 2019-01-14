#!/bin/bash

################################################################
# This script tests ekiden-node.
#
# Usage:
# test_ekiden.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
# NOTE: Need Rust common to initialize the SGX SDK libraries.
source .buildkite/rust/common.sh

# Setup worker and test runtime which is needed to test the worker host.
download_artifact ekiden-worker target/debug 755
download_artifact simple-keyvalue.so target/enclave 755

export EKIDEN_TEST_WORKER_HOST_WORKER_BINARY=$(pwd)/target/debug/ekiden-worker
export EKIDEN_TEST_WORKER_HOST_RUNTIME_BINARY=$(pwd)/target/enclave/simple-keyvalue.so

######################
# Test the ekiden node
######################
pushd go
  make generate
  env -u GOPATH go test -race -coverprofile=coverage.txt -covermode=atomic -v `go list ./... | grep -v github.com/oasislabs/ekiden/go/ekiden`
  pushd ekiden
    env -u GOPATH go test -race -coverpkg ../... -coverprofile=coverage.txt -covermode=atomic -v
  popd
popd

############################
# Upload coverage to codecov
############################
set +x
export CODECOV_TOKEN=$(cat ~/.codecov/ekiden_api_token)
set -x
bash <(curl -s https://codecov.io/bash) -Z
