#!/bin/bash

############################################################
# This script tests the Ekiden rust project.
#
# Usage:
# test_migration.sh [-w <workdir>]
############################################################

# Defaults.
WORKDIR=$(pwd)

#########################
# Process test arguments.
#########################
while getopts 'f:t:' arg
do
    case ${arg} in
        w) WORKDIR=${OPTARG};;
        *)
            echo "Usage: $0 [-w <workdir>]"
            exit 1
    esac
done

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
source .buildkite/scripts/common_e2e.sh
source .buildkite/rust/common.sh

# Runtime identifier.
RUNTIME_ID=0000000000000000000000000000000000000000000000000000000000000000
# Client.
CLIENT="$WORKDIR/target/debug/test-long-term-client"

######################################
# Storage and roothash migration test.
######################################
test_migration() {
    local runtime=simple-keyvalue

    # Start the first network.
    run_backend_tendermint_committee \
        epochtime_backend=tendermint_mock \
        id=1 \
        replica_group_size=1 \
        replica_group_backup_size=0
    sleep 1

    run_compute_node 1 ${runtime} &>/dev/null

    wait_nodes 3 # 1 + storage + km

    set_epoch 1
    sleep 1

    # Start client and do the state mutations.
    ${CLIENT} \
        --mode part1 \
        --node-address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --runtime-id "$RUNTIME_ID"

    # Stop the compute nodes.
    pkill --echo --full --signal 9 worker.compute.backend

    # Export.
    "$WORKDIR/go/ekiden/ekiden" debug roothash export "$RUNTIME_ID" \
        --address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --output_file ${TEST_BASE_DIR}/export-roothash.json

    # Stop all nodes.
    ps efh -C ekiden | awk '{print $1}' | xargs kill -9

    # Re-use storage db in the new storage node.
    mkdir -p ${TEST_BASE_DIR}/committee-2/storage
    chmod 700 ${TEST_BASE_DIR}/committee-2/storage
    cp -a ${TEST_BASE_DIR}/committee-1/storage/storage.leveldb.db ${TEST_BASE_DIR}/committee-2/storage/
    cp -a ${TEST_BASE_DIR}/committee-1/storage/mkvs_storage.leveldb.db ${TEST_BASE_DIR}/committee-2/storage/

    # Start the second network.
    run_backend_tendermint_committee \
        epochtime_backend=tendermint_mock \
        id=2 \
        replica_group_size=1 \
        replica_group_backup_size=0 \
        clear_storage=0 \
        roothash_genesis_blocks="${TEST_BASE_DIR}/export-roothash.json"

    # Finish starting the second network.
    run_compute_node 1 ${runtime} &>/dev/null

    wait_nodes 3 # 1 + storage + km
    set_epoch 2

    # Start client and do state verification, checking that migration succeeded.
    ${CLIENT} \
        --mode part2 \
        --node-address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --runtime-id "$RUNTIME_ID"

    # Cleanup.
    cleanup
}

test_migration
