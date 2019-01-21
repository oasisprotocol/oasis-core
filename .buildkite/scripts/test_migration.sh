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

######################################
# Storage and roothash migration test.
######################################
test_migration() {
    local runtime=simple-keyvalue

    # Start the first network.
    run_backend_tendermint_committee tendermint_mock 1
    sleep 1

    run_compute_node 1 ${runtime} \
        --worker.runtime.replica_group_size 1 \
        --worker.runtime.replica_group_backup_size 0 &>/dev/null

    wait_compute_nodes 1
    set_epoch 1
    sleep 1

    # Link to correct UNIX socket so that we can switch the actual socket later.
    local validator_sock=${TEST_BASE_DIR}/validator.sock
    ln -s ${EKIDEN_VALIDATOR_SOCKET} ${validator_sock}

    # Start long term client, which has a 10-second wait. We run this client so
    # that we test if the migration works without restarting the client.
    "$WORKDIR/target/debug/test-long-term-client" \
        --storage-backend remote \
        --node-address unix:${validator_sock} \
        --mr-enclave "$(cat "$WORKDIR/target/enclave/simple-keyvalue.mrenclave")" \
        --test-runtime-id "$RUNTIME_ID" \
        &
    local client_pid=$(jobs -p +)

    sleep 4
    # 4 sec

    # Stop the compute nodes.
    pkill --echo --full --signal 9 worker.backend

    # Export.
    "$WORKDIR/go/ekiden/ekiden" storage export \
        --address "127.0.0.1:${EKIDEN_STORAGE_PORT}" \
        --output_file ${TEST_BASE_DIR}/export-storage.dat
    "$WORKDIR/go/ekiden/ekiden" debug roothash export "$RUNTIME_ID" \
        --address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --output_file ${TEST_BASE_DIR}/export-roothash.dat

    # Stop the validator and storage nodes.
    pkill --echo --signal 9 ekiden

    sleep 1
    # 5 sec

    # Start the second network.
    run_backend_tendermint_committee tendermint_mock 2 \
        --roothash.genesis_blocks ${TEST_BASE_DIR}/export-roothash.dat

    # Replace validator socket.
    ln -sf ${EKIDEN_VALIDATOR_SOCKET} ${validator_sock}

    sleep 1
    # 6 sec

    # Import storage.
    "$WORKDIR/go/ekiden/ekiden" storage import \
        --address "127.0.0.1:${EKIDEN_STORAGE_PORT}" \
        --input_file ${TEST_BASE_DIR}/export-storage.dat \
        --current_epoch 1

    # Finish starting the second network.
    run_compute_node 1 ${runtime} \
        --worker.runtime.replica_group_size 1 \
        --worker.runtime.replica_group_backup_size 0 &>/dev/null

    sleep 3
    # 9 sec

    wait_compute_nodes 1
    set_epoch 2

    # Wait on the client and check its exit status.
    wait "$client_pid"

    # Cleanup.
    cleanup
}

test_migration
