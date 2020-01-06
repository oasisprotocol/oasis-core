#!/bin/bash
#
# This script pulls the necessary values to start an `oasis-node` client. This involves pulling the
# genesis file from the provided URL, and comparing it with the current genesis file, if it exists.
# If a current genesis file exists, and the a new one has been pulled, then state will be wiped.
#
# Usage: ./scripts/initialize-client/sh <genesis_url> <datadir> <config>

set -o errexit -o nounset -o pipefail

# Get the full path to the root of the oasis-core repository.
ROOT="$(cd $(dirname $0)/..; pwd -P)"

GENESIS_FILENAME="genesis.json"
NEW_GENESIS_FILENAME="new-genesis.json"

GENESIS_URL="$1"
DATADIR="$2"
CONFIG="$3"

curl -Lo ${NEW_GENESIS_FILENAME} ${GENESIS_URL}

if test -f ${GENESIS_FILENAME} && ! cmp -s ${GENESIS_FILENAME} ${NEW_GENESIS_FILENAME}; then
  mv ${NEW_GENESIS_FILENAME} ${GENESIS_FILENAME}
  ${ROOT}/go/oasis-node/oasis-node unsafe-reset --datadir ${DATADIR}
fi

${ROOT}/go/oasis-node/oasis-node --config ${CONFIG}
