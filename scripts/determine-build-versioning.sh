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
    # If the current branch is master then use the git-tag or master and a timestamp
    # Until we start tagging all master merges CIRCLE_TAG doesn't really work with CircleCI
    tag=${CIRCLE_TAG:-master}
    export BUILD_IMAGE_TAG=${tag}-${timestamp}
else
    # Otherwise this is a pull-request and use the sha1
    export BUILD_IMAGE_TAG=${CIRCLE_SHA1}
fi

# Write the docker tag out to a specific file so we can
# save it as an artifact for the build
echo $BUILD_IMAGE_TAG > $1
printf "export BUILD_IMAGE_TAG=%s\n" "$BUILD_IMAGE_TAG" >> $BASH_ENV
