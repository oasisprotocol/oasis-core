#!/bin/bash
##
# Dynamic Buildkite pipeline generator.
##
#
# It outputs valid Buildkite pipeline in YAML format.
#
# To use it, define the following Steps under your Buildkite's Pipeline Settings:
#
# steps:
#   - command: .buildkite/longtests.pipeline.sh
#     label: ":pipeline: Upload"
#
# For more details, see:
# https://buildkite.com/docs/pipelines/defining-steps#dynamic-pipelines.
#

set -eux

epochtime_inverval="${LONGTESTS_EPOCHTIME_INTERVAL:-0}"

cat .buildkite/longtests.pipeline.yml | \
    sed "s/\${epochtime_inverval}/$epochtime_inverval/g" | \
    buildkite-agent pipeline upload
