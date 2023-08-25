#!/bin/bash

################################################################
# This script runs Go lints.
#
# Usage:
# lint.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

##############
# Run golangci
##############
pushd go
  make lint
popd

# Lint doesn't work.
# See: https://github.com/lucas-clemente/quic-go/wiki/quic-go-and-Go-versions
#pushd tests/upgrade
#  make lint
#popd
