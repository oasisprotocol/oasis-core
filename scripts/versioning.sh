#!/bin/bash
set -euxo pipefail

timestamp=`date +%Y%m%d%H%M%S` # YYYYmmddHHMMSS

if [ "$CIRCLE_BRANCH" = "master" ]; then
    # If the current branch is master then use the git-tag and a timestamp
    echo "export DOCKER_TAG=${CIRCLE_TAG}-${timestamp}" >> $BASH_ENV
else
    # Otherwise this is a pull-request and use the sha1
    echo "export DOCKER_TAG=${CIRCLE_SHA1}" >> $BASH_ENV
fi