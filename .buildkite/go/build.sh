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

####################
# Build the Go parts
####################
pushd go
  make all oasis-node/integrationrunner/integrationrunner.test
popd
