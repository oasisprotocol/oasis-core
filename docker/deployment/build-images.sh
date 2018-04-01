#!/bin/bash -e

base_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )

pushd ${base_dir}

# Build the builder Docker image first.
docker build \
    --force-rm \
    -t ekiden/core-builder \
    -f docker/deployment/Dockerfile.build .

# Build the deployable image from the builder image.
docker run \
    --rm ekiden/core-builder \
    | docker build \
        --rm --force-rm \
        -t ekiden/core \
        -

popd
