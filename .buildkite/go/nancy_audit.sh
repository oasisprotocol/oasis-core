#!/bin/bash

############################################################
# This script checks Go.sum for dependencies with
# reported security vulnerabilities.
#
# Usage:
# nancy_audit.sh [path_to_sonatype_oss_index_username] [path_to_sonatype_oss_index_token]
#
# path_to_sonatype_oss_index_username - Absolute or relative
#     path to a file that contains the Sonatype OSS Index
#     account username. Defaults to "~/.sonatype/oss_index_username".
# path_to_sonatype_oss_index_token - Absolute or relative
#     path to a file that contains the Sonatype OSS Index
#     API token. Defaults to "~/.sonatype/oss_index_token".
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

###############
# Optional args
###############
path_to_sonatype_oss_index_username=${1:-~/.sonatype/oss_index_username}
path_to_sonatype_oss_index_token=${2:-~/.sonatype/oss_index_token}

############
# Local vars
############
set +x
sonatype_oss_index_username=$(cat ${path_to_sonatype_oss_index_username})
sonatype_oss_index_token=$(cat ${path_to_sonatype_oss_index_token})
set -x

########################################
# Check dependencies for vulnerabilities
########################################
pushd go/oasis-node
    go list -json -deps | nancy sleuth \
        --username ${sonatype_oss_index_username} \
        --token ${sonatype_oss_index_token} \
        -x ../.nancy-ignore
popd
