#!/bin/bash

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# Working directory.
WORKDIR=$PWD

mkdir -p /tmp/coverage-to-merge

buildkite-agent artifact download "*coverage-*.txt" /tmp/coverage-to-merge
buildkite-agent artifact download "*coverage-e2e-*.tar.gz" /tmp/coverage-to-merge

shopt -s globstar
for f in /tmp/**/*.tar.gz; do
	tar xvzf $f -C /tmp/coverage-to-merge
done
gocovmerge /tmp/coverage-to-merge/coverage-*.txt >merged-coverage.txt
