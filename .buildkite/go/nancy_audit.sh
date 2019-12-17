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
nancy ./go/go.sum