#!/bin/bash

############################################################
# This script tests the Ekiden rust project.
#
# Usage:
# test_migration.sh [-w <workdir>]
############################################################

# Defaults.
WORKDIR=$(pwd)
DUMP_RESTORE_STATE_FILE="/tmp/ekiden-genesis-state.json"

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
        replica_group_backup_size=0 \
        storage_group_size=1
    sleep 1

    run_compute_node 1 ${runtime} &>/dev/null
    run_storage_node 1 &>/dev/null
    # Wait for all nodes to start: 1 compute + 1 storage + 3 validator + key manager.
    wait_nodes 6

    set_epoch 1
    sleep 1

    # Start client and do the state mutations.
    ${CLIENT} \
        --mode part1 \
        --node-address unix:${EKIDEN_CLIENT_SOCKET} \
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
    mkdir -p ${TEST_BASE_DIR}/committee-2/storage-1
    chmod 700 ${TEST_BASE_DIR}/committee-2/storage-1
    cp -a ${TEST_BASE_DIR}/committee-1/storage-1/mkvs_storage.leveldb.db ${TEST_BASE_DIR}/committee-2/storage-1/

    # Start the second network.
    run_backend_tendermint_committee \
        epochtime_backend=tendermint_mock \
        id=2 \
        replica_group_size=1 \
        replica_group_backup_size=0 \
        storage_group_size=1 \
        roothash_genesis_blocks="${TEST_BASE_DIR}/export-roothash.json"

    # Finish starting the second network.
    run_compute_node 1 ${runtime} &>/dev/null
    run_storage_node 1 clear_storage=0 &>/dev/null
    # Wait for all nodes to start: 1 compute + 1 storage + 3 validator + key manager.
    wait_nodes 6

    set_epoch 2

    # Start client and do state verification, checking that migration succeeded.
    ${CLIENT} \
        --mode part2 \
        --node-address unix:${EKIDEN_CLIENT_SOCKET} \
        --runtime-id "$RUNTIME_ID"

    # Cleanup.
    cleanup
}

################################
# BFT state dump & restore test.
################################
test_dumprestore() {
    local runtime=simple-keyvalue

    # Make sure no leftover state is present from before.
    rm -f "${DUMP_RESTORE_STATE_FILE}"
    rm -rf "${TEST_BASE_DIR}"/committee* export-roothash.json

    # Start the first network.
    run_backend_tendermint_committee \
        epochtime_backend=tendermint_mock \
        id=1 \
        replica_group_size=1 \
        replica_group_backup_size=0 \
        storage_group_size=1
    sleep 1

    run_compute_node 1 ${runtime} &>/dev/null
    run_storage_node 1 &>/dev/null
    # Wait for all nodes to start: 1 compute + 1 storage + 3 validator + key manager.
    wait_nodes 6

    set_epoch 1
    sleep 1

    # Start client and do the state mutations.
    ${CLIENT} \
        --mode part1 \
        --node-address unix:${EKIDEN_CLIENT_SOCKET} \
        --runtime-id "$RUNTIME_ID"

    # Stop the compute nodes.
    pkill --echo --full --signal 9 worker.compute.backend

    # Dump BFT state.
    "$WORKDIR/go/ekiden/ekiden" genesis dump \
        --height 0 --genesis_file "${DUMP_RESTORE_STATE_FILE}" \
        --address unix:${EKIDEN_VALIDATOR_SOCKET}

    # Stop all nodes.
    ps efh -C ekiden | awk '{print $1}' | xargs kill -9

    # Re-use storage db in the new storage node.
    mkdir -p ${TEST_BASE_DIR}/committee-2/storage-1
    chmod 700 ${TEST_BASE_DIR}/committee-2/storage-1
    cp -a ${TEST_BASE_DIR}/committee-1/storage-1/mkvs_storage.leveldb.db ${TEST_BASE_DIR}/committee-2/storage-1/

    # Make sure the identities are the same.
    mkdir -p ${TEST_BASE_DIR}/committee-2/committee-data-{1,2,3}/
    mkdir -p ${TEST_BASE_DIR}/committee-2/entity
    mkdir -p ${TEST_BASE_DIR}/committee-2/key-manager
    mkdir -p ${TEST_BASE_DIR}/committee-2/seed-2
    mkdir -p ${TEST_BASE_DIR}/committee-2/worker-1
    mkdir -p ${TEST_BASE_DIR}/committee-2/client-1
    chmod 700 ${TEST_BASE_DIR}/committee-2/committee-data-{1,2,3}/
    chmod 700 ${TEST_BASE_DIR}/committee-2/entity
    chmod 700 ${TEST_BASE_DIR}/committee-2/key-manager
    chmod 700 ${TEST_BASE_DIR}/committee-2/seed-2
    chmod 700 ${TEST_BASE_DIR}/committee-2/worker-1
    chmod 700 ${TEST_BASE_DIR}/committee-2/client-1
    cp -a ${TEST_BASE_DIR}/committee-1/committee-data-1/*.pem ${TEST_BASE_DIR}/committee-2/committee-data-1/
    cp -a ${TEST_BASE_DIR}/committee-1/committee-data-2/*.pem ${TEST_BASE_DIR}/committee-2/committee-data-2/
    cp -a ${TEST_BASE_DIR}/committee-1/committee-data-3/*.pem ${TEST_BASE_DIR}/committee-2/committee-data-3/
    cp -a ${TEST_BASE_DIR}/committee-1/entity/entity.{json,pem} ${TEST_BASE_DIR}/committee-2/entity/
    cp -a ${TEST_BASE_DIR}/committee-1/key-manager/*.pem ${TEST_BASE_DIR}/committee-2/key-manager/
    cp -a ${TEST_BASE_DIR}/committee-1/seed-1/*.pem ${TEST_BASE_DIR}/committee-2/seed-2/
    cp -a ${TEST_BASE_DIR}/committee-1/worker-1/*.pem ${TEST_BASE_DIR}/committee-2/worker-1/
    cp -a ${TEST_BASE_DIR}/committee-1/client-1/*.pem ${TEST_BASE_DIR}/committee-2/client-1/
    cp -a ${TEST_BASE_DIR}/committee-1/storage-1/*.pem ${TEST_BASE_DIR}/committee-2/storage-1/

    # Start the second network.
    run_backend_tendermint_committee \
        epochtime_backend=tendermint_mock \
        id=2 \
        replica_group_size=1 \
        replica_group_backup_size=0 \
        storage_group_size=1 \
        restore_genesis_file="${DUMP_RESTORE_STATE_FILE}"

    # Finish starting the second network.
    run_compute_node 1 ${runtime} &>/dev/null
    run_storage_node 1 clear_storage=0 &>/dev/null
    # Wait for all nodes to start: 1 compute + 1 storage + 3 validator + key manager.
    wait_nodes 6

    set_epoch 2

    # Start client and do state verification, checking that migration succeeded.
    ${CLIENT} \
        --mode part2 \
        --node-address unix:${EKIDEN_CLIENT_SOCKET} \
        --runtime-id "$RUNTIME_ID"

    # Cleanup.
    rm -f "${DUMP_RESTORE_STATE_FILE}"
    cleanup
}

test_migration
test_dumprestore
