#!/bin/bash

################################################################
# This script builds ekiden-node.
#
# Usage:
# build_ekiden.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

#######################
# Build the ekiden node
#######################
pushd go
  make
popd
