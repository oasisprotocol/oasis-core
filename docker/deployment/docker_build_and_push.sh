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

###############
# Optional args
###############
path_to_ssh_private_key=${3:-~/.ssh/id_rsa}

#################
# Local variables
#################
docker_image_name=oasislabs/testnet

####################################
# Build and publish the docker image
####################################

set +x
# The docker command will contain the ssh private key
# in plain text and we don't want that getting into bash
# history, so we intentionally disable printing commands
# with set +x.
# TODO: Support non-simulation builds.
docker build --rm --force-rm \
  --build-arg SSH_PRIVATE_KEY="$(cat ${path_to_ssh_private_key})" \
  --build-arg SGX_MODE=SIM \
  --build-arg EKIDEN_SKIP_AVR_VERIFY=1 \
  --build-arg EKIDEN_COMMIT_SHA=${git_commit_sha} \
  --build-arg EKIDEN_BUILD_IMAGE_TAG=${docker_image_tag} \
  -t ${docker_image_name}:${docker_image_tag} \
  docker/deployment
set -x

docker push ${docker_image_name}:${docker_image_tag}

# Remove the intermediate docker images that contain
# the private SSH key
docker rmi -f $(docker images -q --filter label=stage=builder)
