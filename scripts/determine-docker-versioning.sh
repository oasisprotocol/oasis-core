#!/bin/bash
##
# This is a build script to determine the docker tag to use for versioning the
# docker image. This will write to an output file that can be used as an artifact
# between build steps
#
# Usage determine-docker-versioning.sh [path-to-output-file]
##

set -euxo pipefail

timestamp=`date +%Y%m%d%H%M%S` # YYYYmmddHHMMSS

if [ "$CIRCLE_BRANCH" = "master" ]; then
    # If the current branch is master then use the git-tag and a timestamp
    export DOCKER_TAG=${CIRCLE_TAG}-${timestamp}
else
    # Otherwise this is a pull-request and use the sha1
    export DOCKER_TAG=${CIRCLE_SHA1}
fi

# Write the docker tag out to a specific file so we can
# save it as an artifact for the build
echo $DOCKER_TAG > $1
printf "export DOCKER_TAG=%s\n" "$DOCKER_TAG" >> $BASH_ENV