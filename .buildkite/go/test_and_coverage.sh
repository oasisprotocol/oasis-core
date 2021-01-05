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
download_artifact simple-keyvalue target/debug 755

export OASIS_TEST_RUNTIME_HOST_RUNTIME_PATH=$(pwd)/target/debug/simple-keyvalue

#####################
# Test the Oasis node
#####################
pushd go
  make generate
  # We need to do multiple test passes for different parts to get correct coverage.
  env -u GOPATH go test -race -coverprofile=../coverage-misc.txt -covermode=atomic -v \
    $(go list ./... | \
        grep -v github.com/oasisprotocol/oasis-core/go/oasis-node | \
        grep -v github.com/oasisprotocol/oasis-core/go/genesis | \
        grep -v github.com/oasisprotocol/oasis-core/go/storage/mkvs )
  # Oasis node tests.
  pushd oasis-node
    env -u GOPATH go test -race -coverpkg ../... -coverprofile=../../coverage-oasis-node.txt -covermode=atomic -v ./...
  popd
  pushd genesis
    env -u GOPATH go test -race -coverpkg ../... -coverprofile=../../coverage-genesis.txt -covermode=atomic -v ./...
  popd
  # MKVS tests.
  pushd storage/mkvs
    env -u GOPATH go test -race -coverpkg ./... -coverprofile=../../../coverage-mkvs.txt -covermode=atomic -v ./...
  popd
popd
