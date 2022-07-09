#!/bin/bash

############################################################
# This script checks Go.sum for dependencies with
# reported security vulnerabilities.
#
# Usage:
# nancy_audit.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

########################################
# Check dependencies for vulnerabilities
########################################
pushd go/oasis-node
    go list -json -deps | nancy sleuth -x ../.nancy-ignore
popd
