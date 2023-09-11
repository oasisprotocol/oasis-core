#!/bin/bash

################################################################
# This script builds Go parts.
#
# Usage:
# build.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

RED='\033[0;31m'
OFF='\033[0m'

####################
# Build the Go parts
####################
pushd go
  # Ensure that the `go generate` output in git is up-to-date.
  make generate
  if [ -n "$(git status --porcelain)" ]; then
    echo -e "${RED}ERROR: go/ directory is dirty after 'go generate'${OFF}"
    git diff
    exit 1
  fi

  make all GO_BUILD_E2E_COVERAGE=1
popd

pushd tests/upgrade
  # Use legacy Go toolchain for pre-upgrade tests.
  OASIS_GO=go1.20.2 make -C pre
  # Use regular Go toolchain for post-upgrade tests.
  make -C post
popd
