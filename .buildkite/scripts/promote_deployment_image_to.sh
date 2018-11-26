#! /bin/bash

#############################################
# Gets the deployment image tag from buildkite
# metadata and promotes the deployment image
# by retagging it with the provided tag.
#
# This script is intended to have buildkite
# specific things, like env vars and calling
# the buildkite-agent binary. Keeping this
# separate from the generic script that gets
# called allows us to use and test the generic
# scripts easily on a local dev box.
##############################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

####################
# Required arguments
####################
new_image_tag=$1

#################
# Local variables
#################
docker_image_name=oasislabs/testnet
deployment_image_tag=$(buildkite-agent meta-data \
                       get \
                       "deployment_image_tag"
                     )

##############################################
# Add the provided tag to the deployment image
##############################################

docker pull "${docker_image_name}:${deployment_image_tag}"

docker tag \
  "${docker_image_name}:${deployment_image_tag}" \
  "${docker_image_name}:${new_image_tag}"

docker push "${docker_image_name}:${new_image_tag}"
