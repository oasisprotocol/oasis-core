#!/bin/bash

############################################################
# This script checks that ekiden crates have the same
# version configured in Cargo.toml.
#
# Usage:
# lint_crate_versions.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

##################################
# Check for crate version equality
##################################
test `find . -name "Cargo.toml" -print0 | xargs -0 grep '^version = "' | cut -d'"' -f2 | sort | uniq | wc -l` == 1
