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
