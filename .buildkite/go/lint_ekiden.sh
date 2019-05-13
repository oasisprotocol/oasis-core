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
  make generate

  MODIFIED=$(git diff --name-only HEAD | grep .pb.go) || true
  if [ ! -z $MODIFIED ]; then
      echo "GRPC generated files differ from the ones provided in this commit"
      echo "Please run \"make generate\" and try again"
      exit 1
  fi

  make lint
popd
