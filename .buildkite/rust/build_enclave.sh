#!/bin/bash

############################################################
# This script builds a generic Rust enclave.
#
# Usage:
# build_enclave.sh <src_dir>
#
# src_dir - Absolute or relative path to the directory
#           containing the source code.
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

###############
# Required args
###############
src_dir=$1
if [ ! -d $src_dir ]; then
  echo "ERROR: Invalid source directory specified (${src_dir})."
  exit 1
fi
shift

#########################################
# Additional args passed to `cargo build`
#########################################
extra_args=$*

source .buildkite/rust/common.sh

#################################################################
# Ensure we have ekiden-tools installed, needed to build enclaves
#################################################################
cargo install \
    --force \
    --path tools \
    --debug

###############
# Run the build
###############
pushd $src_dir
  cargo ekiden build-enclave --output-identity $extra_args
popd
