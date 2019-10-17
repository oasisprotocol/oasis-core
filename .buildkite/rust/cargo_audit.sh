#!/bin/bash

############################################################
# This script checks Cargo.lock for dependencies with
# reported security vulnerabilities.
#
# Usage:
# cargo_audit.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

########################################
# Check dependencies for vulnerabilities
########################################
cargo audit
