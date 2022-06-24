#!/bin/bash

# TODO Update build scripts to be DRY.

#################################################
# This script uses Tarpaulin to calculate test
# coverage in the code base.
#
# Usage:
# code_coverage.sh [path_to_coveralls_api_token]
#
# path_to_coveralls_api_token - Absolute or relative
#     path to a file that contains the coveralls.io
#     API token. Defaults to "~/.coveralls/api_token".
#################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/rust/common.sh

###############
# Optional args
###############
path_to_coveralls_api_token=${1:-~/.coveralls/oasis_core_api_token}

############
# Local vars
############
set +x
coveralls_api_token=$(cat ${path_to_coveralls_api_token})
set -x

# We need to use a separate target dir for tarpaulin as it otherwise clears
# the build cache.
export CARGO_TARGET_DIR=/tmp/coverage_target

# Required as tarpaulin doesn't honor .cargo/config.
export RUSTFLAGS="-C target-feature=+aes,+ssse3"

# Make sure we can run unit tests for production enclaves.
unset OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES

# Name the current commit so Tarpaulin can detect it correctly.
git checkout -B ${BUILDKITE_BRANCH}

# Calculate coverage.
set +x
cargo tarpaulin \
  --locked \
  --ignore-tests \
  --out Xml \
  --all \
  --avoid-cfg-tarpaulin \
  --exclude simple-keyvalue \
  --exclude-files '*generated*' \
  --exclude-files tests \
  --exclude-files runtime/fuzz \
  --exclude-files runtime/src/storage/mkvs/interop \
  --exclude-files tools \
  --coveralls ${coveralls_api_token} \
  -v
set -x
