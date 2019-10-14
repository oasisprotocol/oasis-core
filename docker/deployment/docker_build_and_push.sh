#! /bin/bash

#########################################
# 1. Builds a new deployment image of
#    oasislabs/testnet
#    and tags it with the provided tag.
# 2. Push deployment image to Docker Hub.
#########################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

###############
# Required args
###############
git_commit_sha=$1
docker_image_tag=$2
context=$3

#################
# Local variables
#################
docker_image_name=oasislabs/testnet

####################################
# Build and publish the docker image
####################################

docker build --pull --rm --force-rm \
  --build-arg OASIS_CORE_COMMIT_SHA=${git_commit_sha} \
  --build-arg OASIS_CORE_BUILD_IMAGE_TAG=${docker_image_tag} \
  -t ${docker_image_name}:${docker_image_tag} \
  --file=docker/deployment/Dockerfile \
  - <"$context"

docker push ${docker_image_name}:${docker_image_tag}
