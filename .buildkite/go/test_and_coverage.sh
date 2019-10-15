#!/bin/bash

################################################################
# This script tests oasis-node.
#
# Usage:
# test_and_coverage.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
# NOTE: Need Rust common to initialize the SGX SDK libraries.
source .buildkite/rust/common.sh

# Setup worker and test runtime which is needed to test the worker host.
download_artifact oasis-core-runtime-loader target/debug 755
download_artifact simple-keyvalue target/debug 755

export OASIS_TEST_WORKER_HOST_WORKER_BINARY=$(pwd)/target/debug/oasis-core-runtime-loader
export OASIS_TEST_WORKER_HOST_RUNTIME_BINARY=$(pwd)/target/debug/simple-keyvalue

#####################
# Test the Oasis node
#####################
pushd go
  make generate
  # We need to do multiple test passes for different parts to get correct coverage.
  env -u GOPATH go test -race -coverprofile=coverage.txt -covermode=atomic -v \
    $(go list ./... | \
        grep -v github.com/oasislabs/oasis-core/go/oasis-node | \
        grep -v github.com/oasislabs/oasis-core/go/storage/mkvs/urkel )
  # Oasis node tests.
  pushd oasis-node
    env -u GOPATH go test -race -coverpkg ../... -coverprofile=coverage.txt -covermode=atomic -v ./...
  popd
  # Urkel tree tests.
  pushd storage/mkvs/urkel
    env -u GOPATH go test -race -coverpkg ./... -coverprofile=coverage.txt -covermode=atomic -v ./...
  popd
popd

############################
# Upload coverage to codecov
############################
set +x
export CODECOV_TOKEN=$(cat ~/.codecov/oasis_core_api_token)
set -x
bash <(curl -s https://codecov.io/bash) -Z
