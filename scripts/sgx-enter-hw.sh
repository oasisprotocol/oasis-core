#!/bin/bash -e

# Working directory is determined by using git, so we can use the same script
# with external repositories which use their own root.
WORK_DIR=$( git rev-parse --show-toplevel )
# Name of the ekiden container.
EKIDEN_CONTAINER_NAME=${EKIDEN_CONTAINER_NAME:-$(basename ${WORK_DIR})}

ekiden_image=${EKIDEN_DOCKER_IMAGE:-ekiden/development:0.1.0-alpha.3}
ekiden_shell=${EKIDEN_DOCKER_SHELL:-bash}

# Setting the environment variable EKIDEN_DOCKER_DETACH_KEYS to
# something like 'ctrl-[,ctrl-q' will change it from the default of
# ctrl-p,ctrl-q which can be annoying to bash users used to
# emacs-style previous-history (as opposed to using up-arrow) to go
# back through the command history.  NB: it would be bad if the
# environment variable contained spaces.

DETACH=${EKIDEN_DOCKER_DETACH_KEYS:+"--detach-keys ${EKIDEN_DOCKER_DETACH_KEYS}"}

which docker >/dev/null || {
  echo "ERROR: Please install Docker first."
  exit 1
}

# https://forums.docker.com/t/how-to-filter-docker-ps-by-exact-name/2880/7
container_filter='name=^/'"$EKIDEN_CONTAINER_NAME"'$'

# Start SGX Rust Docker container.
if [ ! "$(docker ps -q -f "$container_filter")" ]; then
  if [ "$(docker ps -aq -f "$container_filter")" ]; then
    docker start ${EKIDEN_CONTAINER_NAME}
    docker exec -i -t ${DETACH} ${EKIDEN_CONTAINER_NAME} /usr/bin/env $ekiden_shell
  else
    # privileged for aesmd
    docker run -t -i \
      --privileged \
      --name "${EKIDEN_CONTAINER_NAME}" \
      -v ${WORK_DIR}:/code \
      -e "SGX_MODE=HW" \
      -e "INTEL_SGX_SDK=/opt/sgxsdk" \
      -w /code \
      ${DETACH} \
      "$ekiden_image" \
      /usr/bin/env $ekiden_shell
  fi
else
  docker exec -i -t ${DETACH} ${EKIDEN_CONTAINER_NAME} /usr/bin/env $ekiden_shell
fi
