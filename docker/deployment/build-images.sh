#!/bin/bash -e

ekiden_image=${EKIDEN_DOCKER_IMAGE:-ekiden/development:0.1.0-alpha.3}
base_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )

cd ${base_dir}

if [ -n "$BUILD_IMAGES_NO_ENTER" ]; then
    ./docker/deployment/build-images-inner.sh
elif [ -z "$BUILD_IMAGES_CONTAINER" ]; then
    # Build in a fresh container.
    docker run --rm \
        -v .:/code \
        -e SGX_MODE=SIM \
        -e INTEL_SGX_SDK=/opt/sgxsdk \
        -w /code \
        "$ekiden_image" \
        /code/docker/deployment/build-images-inner.sh
else
    # Build in a specified container.
    docker exec "$BUILD_IMAGES_CONTAINER" \
        /code/docker/deployment/build-images-inner.sh
fi

# Build the deployable image from the output.
docker build --rm --force-rm -t oasislabs/testnet - <target/deployment.tar.gz
