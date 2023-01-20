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
      ':(exclude).punch_version.py' \
      ':(exclude)docs/' \
      ':(exclude)towncrier.toml' \
      ':(exclude).gitbook.yaml'
}

# Helper that checks if anything under docker/ has been modified in a pull request.
pr_and_docker_changes() {
  # Check if the build was triggered for a pull request.
  if [[ -z $BUILDKITE_PULL_REQUEST_BASE_BRANCH ]]; then
    return 1
  fi
  # Get the list of changed files under docker/.
  ! git diff --name-only --exit-code "refs/remotes/origin/$BUILDKITE_PULL_REQUEST_BASE_BRANCH.." 1>&2 -- \
    'docker/'
}

# Helper that checks if the given tag of the oasisprotocol/oasis-core-ci Docker image exists.
check_docker_ci_image_tag_exists() {
  local tag=$1
  curl --silent -f --head -lL "https://hub.docker.com/v2/repositories/oasisprotocol/oasis-core-ci/tags/${tag}/"
}

# Determine the oasis-core-ci Docker image tag to use for tests.
if [[ -n $BUILDKITE_PULL_REQUEST_BASE_BRANCH ]]; then
  docker_tag=${BUILDKITE_PULL_REQUEST_BASE_BRANCH//\//-}
else
  docker_tag=${BUILDKITE_BRANCH//\//-}
fi

# If anything under docker/ has been modified, assume a per-branch tag. Note that this will fail until
# the corresponding GitHub Action that rebuilds the Docker images runs.
if pr_and_docker_changes; then
  # Override the Docker tag that should be used.
  docker_tag=pr-$(git describe --always --match '' --abbrev=7)
  # Fail if the Docker image does not exist.
  if ! check_docker_ci_image_tag_exists "${docker_tag}"; then
    echo 1>&2 "Updated Docker image does not yet exist. Wait for it to be rebuilt and retry."
    exit 1
  fi
fi

if ! check_docker_ci_image_tag_exists "${docker_tag}"; then
    echo 1>&2 "Docker image 'oasisprotocol/oasis-core-ci:${docker_tag}' does not exist."
    exit 1
fi

export DOCKER_OASIS_CORE_CI_BASE_TAG=${docker_tag}

# Decide which pipeline to use.
pipeline=.buildkite/code.pipeline.yml
if pr_and_no_code_related_changes; then
    pipeline=.buildkite/code-skip.pipeline.yml
fi

# Upload the selected pipeline.
cat $pipeline | buildkite-agent pipeline upload

