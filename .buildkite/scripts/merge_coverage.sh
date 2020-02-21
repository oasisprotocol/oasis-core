#!/bin/bash

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

mkdir -p /tmp/coverage-to-merge

buildkite-agent artifact download "*coverage-*.txt" /tmp/coverage-to-merge

gocovmerge /tmp/coverage-to-merge/coverage-*.txt >merged-coverage.txt
