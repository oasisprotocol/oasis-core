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

# Instal Tarpaulin
# TODO: This should be installed into the testing image.
RUSTFLAGS="--cfg procmacro2_semver_exempt" \
  cargo install \
  --git https://github.com/oasislabs/tarpaulin \
  --branch ekiden \
  cargo-tarpaulin

# Calculate coverage
set +x
cargo tarpaulin \
  --ignore-tests \
  --out Xml \
  --packages ekiden-common \
  --packages ekiden-db-trusted \
  --packages ekiden-di \
  --packages ekiden-enclave-common \
  --packages ekiden-enclave-logger \
  --packages ekiden-enclave-trusted \
  --packages ekiden-rpc-client \
  --packages ekiden-rpc-common \
  --packages ekiden-rpc-trusted \
  --packages ekiden-runtime-client \
  --packages ekiden-runtime-common \
  --packages ekiden-runtime-trusted \
  --packages ekiden-storage-base \
  --packages ekiden-storage-batch \
  --packages ekiden-storage-frontend \
  --packages ekiden-storage-lru \
  --packages ekiden-storage-multilayer \
  --packages ekiden-storage-persistent \
  --packages ekiden-tools \
  --exclude-files *generated* \
  --exclude-files compute/* \
  --exclude-files key-manager/* \
  --exclude-files registry/* \
  --exclude-files scheduler/* \
  --exclude-files stake/* \
  --coveralls ${coveralls_api_token} \
  -v
set -x
