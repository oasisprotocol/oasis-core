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
#   - command: .buildkite/pipeline.sh | buildkite-agent pipeline upload
#     label: ":pipeline: Upload"
#
# For more details, see:
# https://buildkite.com/docs/pipelines/defining-steps#dynamic-pipelines.
#

set -eux

# Helper that ensures the build is triggered for a pull request and that there
# are no code-related changes compared to the pull request's base branch.
pr_and_no_code_related_changes() {
  # Check if the build was triggered for a pull request.
  if [[ -z $BUILDKITE_PULL_REQUEST_BASE_BRANCH ]]; then
    return 1
  fi
  # Get the list of changes files, excluding changes unrelated to code.
  # NOTE: The exclude patterns below use git's pathspec syntax:
  # https://git-scm.com/docs/gitglossary#Documentation/gitglossary.txt-aiddefpathspecapathspec.
  git diff --name-only --exit-code "refs/remotes/origin/$BUILDKITE_PULL_REQUEST_BASE_BRANCH.." 1>&2 -- \
      ':(exclude)*.md' \
      ':(exclude).changelog/' \
      ':(exclude).github/' \
      ':(exclude).gitlint' \
      ':(exclude).markdownlint.yml' \
      ':(exclude).punch_config.py' \
      ':(exclude)docs/' \
      ':(exclude)towncrier.toml'
}

if pr_and_no_code_related_changes; then
    cat .buildkite/code-skip.pipeline.yml
else
    cat .buildkite/code.pipeline.yml
fi
