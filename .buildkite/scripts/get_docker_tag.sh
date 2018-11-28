#!/bin/bash
##
# This is a build script to determine the value of the tag
# to use when versioning the docker image.
#
# The value of the tag will be echo'd to stdout
# so that the calling script can do something useful
# with it. For example, make it available elsewhere
# in the pipeline by saving it as an artifact/meta-data/etc.
#
# Usage:
# get_docker_tag.sh [git_branch] [git_commit_sha] [git_tag]
##

# get_docker_tag $BUILDKITE_BRANCH $BUILDKITE_COMMIT $BUILDKITE_TAG

set -euo pipefail

git_branch_name=$1
git_commit_sha=$2
git_tag_name=${3:-NO_TAG_PROVIDED}

# TODO possibly change to more human readable format:
#      YYYY-mm-dd-HH-MM-SS
timestamp=`date +%Y%m%d%H%M%S` # YYYYmmddHHMMSS

if [ ${git_branch_name} = "master" ]; then
    # If the current branch IS master, then we
    # use a special value as the tag for the docker image.

    # Use the current git tag as a prefix if it is
    # defined. If not, use "master" as a default.
    if [ ${git_tag_name} = "NO_TAG_PROVIDED" ]; then
      prefix="master"
    else
      prefix=${git_tag_name}
    fi

    # Concat prefix and timestamp.
    docker_image_tag=${prefix}-${timestamp}
else
    # If the current branch IS NOT master, then
    # it is a pull request or feature branch.
    # Use the git commit SHA1 as the tag for the docker image.
    docker_image_tag=${git_commit_sha}
fi

# Echo the final tag value to stdout
# so that the calling script can do
# something useful with it.
echo "${docker_image_tag}"
