#!/bin/bash

############################################################
# This script tests the Oasis Core project with the consensus
# simulator.
#
# Usage:
# test_consim.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# Working directory.
WORKDIR=$PWD

#################
# Run test suite.
#################

echo ${WORKDIR}

CONSIM_GENESIS=/tmp/consim-genesis.json

# Generate the consensus sim genesis document.
${WORKDIR}/go/oasis-node/oasis-node \
    genesis init \
    --debug.test_entity \
    --debug.dont_blame_oasis \
    --chain.id test \
    --debug.allow_test_keys \
    --staking.token_symbol BUF \
    -g ${CONSIM_GENESIS}

# Run the consensus simulator.
${WORKDIR}/go/oasis-node/oasis-node \
    debug consim \
    --datadir /tmp/consim-datadir \
    --log.level DEBUG \
    --log.file /tmp/consim-datadir/consim.log \
    -g ${CONSIM_GENESIS} \
    --debug.dont_blame_oasis \
    --debug.allow_test_keys \
    --consim.workload xfer \
    --consim.workload.xfer.iterations 10000 \
    --consim.num_kept 1 \
    --consim.memdb
