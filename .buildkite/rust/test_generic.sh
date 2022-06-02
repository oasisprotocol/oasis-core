#!/bin/bash

############################################################
# This script tests the Rust parts.
#
# Usage:
# test_generic.sh <src-dir>
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

# Make sure we can run unit tests for production enclaves.
unset OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES

#########################
# Run the build and tests
#########################
pushd $src_dir
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR}/default" cargo build --all --locked --exclude simple-keyvalue
  cargo fmt -- --check
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR}/default" cargo test --all --locked --exclude simple-keyvalue
popd
