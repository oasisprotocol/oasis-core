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
path_to_coveralls_api_token=${1:-~/.coveralls/ekiden_api_token}

############
# Local vars
############
set +x
coveralls_api_token=$(cat ${path_to_coveralls_api_token})
set -x

# We need to use a separate target dir for tarpaulin as it otherwise clears
# the build cache.
export CARGO_TARGET_DIR=/tmp/coverage_target

# Calculate coverage
set +x
cargo tarpaulin \
  --ignore-tests \
  --out Xml \
  --exclude-files *generated* \
  --coveralls ${coveralls_api_token} \
  -v
set -x
