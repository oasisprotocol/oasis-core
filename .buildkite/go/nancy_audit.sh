#!/bin/bash

############################################################
# This script checks Go.sum for dependencies with
# reported security vulnerabilities.
#
# Usage:
# nancy_audit.sh
#
# Expects Sonatype OSS Index account username and API token in
# "~/.sonatype/oss_index_username" and "~/.sonatype/oss_index_token".
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

#######################
# Environment variables
#######################
set +x
OSSI_USERNAME=$(cat ~/.sonatype/oss_index_username)
OSSI_TOKEN=$(cat ~/.sonatype/oss_index_token)
export OSSI_USERNAME
export OSSI_TOKEN
set -x

########################################
# Check dependencies for vulnerabilities
########################################
pushd go/oasis-node
    go list -json -deps | nancy sleuth -x ../.nancy-ignore
popd
