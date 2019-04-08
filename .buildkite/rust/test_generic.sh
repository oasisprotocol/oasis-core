#!/bin/bash

############################################################
# This script tests the Ekiden rust project.
#
# Usage:
# test_ekiden.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/rust/common.sh

###############
# Required args
###############
src_dir=$1
if [ ! -d $src_dir ]; then
  echo "ERROR: Invalid source directory specified (${src_dir})."
  exit 1
fi
shift

#########################
# Run the build and tests
#########################
pushd $src_dir
  cargo build --all --exclude simple-keyvalue
  cargo fmt -- --check
  cargo test --all --exclude simple-keyvalue
popd
