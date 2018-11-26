#!/bin/bash

################################################################
# This script sets up gitconfig for Buildkite
#
# Usage:
# setup_gitconfig.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# Setup the Git configuration
cat >/root/.gitconfig <<EOF
# This is required for the CI/CD build agents
# to run cargo build because the Cargo.toml
# files declare dependencies to private git
# repos using https:// and the build agents
# use SSH keys to access those repos on GitHub.
[url "ssh://git@github.com"]
  insteadOf = https://github.com
EOF
