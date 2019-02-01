#!/bin/bash

################################################################
# This script lints Git commits
#
# Usage:
# lint_git.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

#############
# Run gitlint
#############
echo "Linting from $(git rev-parse origin/master)"
gitlint --commits origin/master...HEAD
