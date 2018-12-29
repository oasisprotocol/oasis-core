#!/bin/bash

############################################################
# This script tests the Ekiden rust project.
#
# Usage:
# test_migration.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
source .buildkite/scripts/common_e2e.sh
source .buildkite/rust/common.sh

# Working directory.
WORKDIR=${1:-$(pwd)}

# Runtime identifier.
RUNTIME_ID=0000000000000000000000000000000000000000000000000000000000000000

test_migration() {
    local epochtime_backend=$1
    local beacon_backend=$2
    local registry_backend=$3
    local roothash_backend=$4

    local datadir=/tmp/ekiden-dummy-data

    # Start the first dummy network.
    rm -rf "$datadir"
    "$WORKDIR/go/ekiden/ekiden" \
        --log.level debug \
        --grpc.port 42261 \
        --epochtime.backend "$epochtime_backend" \
        --beacon.backend "$beacon_backend" \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend "$registry_backend" \
        --roothash.backend "$roothash_backend" \
        --tendermint.consensus.timeout_commit 250ms \
        --datadir "$datadir" \
        &
    local first_dummy_pid=$(jobs -p +)

    sleep 1

    "$WORKDIR/target/debug/ekiden-compute" \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir $(mktemp -d) \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10001 \
        --disable-key-manager \
        --test-runtime-id "$RUNTIME_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local first_compute1_pid=$(jobs -p +)

    "$WORKDIR/target/debug/ekiden-compute" \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir $(mktemp -d) \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10002 \
        --disable-key-manager \
        --test-runtime-id "$RUNTIME_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local first_compute2_pid=$(jobs -p +)

    sleep 3

    "${WORKDIR}/go/ekiden/ekiden" debug dummy wait-nodes --nodes 2
    "$WORKDIR/go/ekiden/ekiden" debug dummy set-epoch --epoch 1

    sleep 2

    # Start long term client, which has a 10-second wait.
    "$WORKDIR/target/debug/test-long-term-client" \
        --storage-backend remote \
        --mr-enclave "$(cat "$WORKDIR/target/enclave/token.mrenclave")" \
        --test-runtime-id "$RUNTIME_ID" \
        &
    local client_pid=$(jobs -p +)

    sleep 2
    # 2 sec

    # Stop the network.
    kill "$first_compute1_pid" "$first_compute2_pid"
    wait "$first_compute1_pid" "$first_compute2_pid" || true

    # Export.
    "$WORKDIR/go/ekiden/ekiden" storage export --output_file /tmp/ekiden-test-storage.dat
    "$WORKDIR/go/ekiden/ekiden" debug roothash export "$RUNTIME_ID" --output_file /tmp/ekiden-test-roothash.dat

    # Finish tearing down the network.
    kill -KILL "$first_dummy_pid"
    wait "$first_dummy_pid" || true

    sleep 1
    # 3 sec

    # Start the second dummy node.
    rm -rf "$datadir"
    "$WORKDIR/go/ekiden/ekiden" \
        --log.level debug \
        --grpc.port 42261 \
        --epochtime.backend "$epochtime_backend" \
        --beacon.backend "$beacon_backend" \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend "$registry_backend" \
        --roothash.backend "$roothash_backend" \
        --roothash.genesis_blocks /tmp/ekiden-test-roothash.dat \
        --tendermint.consensus.timeout_commit 250ms \
        --datadir "$datadir" \
        &
    local second_dummy_pid=$(jobs -p +)

    sleep 1
    # 4 sec

    # Import.
    "$WORKDIR/go/ekiden/ekiden" storage import --input_file /tmp/ekiden-test-storage.dat --current_epoch 1

    # Finish starting the second network.
    "$WORKDIR/target/debug/ekiden-compute" \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir $(mktemp -d) \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10001 \
        --disable-key-manager \
        --test-runtime-id "$RUNTIME_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local second_compute1_pid=$(jobs -p +)

    "$WORKDIR/target/debug/ekiden-compute" \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir $(mktemp -d) \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10002 \
        --disable-key-manager \
        --test-runtime-id "$RUNTIME_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local second_compute2_pid=$(jobs -p +)

    sleep 3
    # 7 sec

    "${WORKDIR}/go/ekiden/ekiden" debug dummy wait-nodes --nodes 2
    "$WORKDIR/go/ekiden/ekiden" debug dummy set-epoch --epoch 2

    # Wait on the client and check its exit status.
    wait "$client_pid"

    # Cleanup.
    cleanup
}

test_migration mock insecure memory memory
test_migration tendermint_mock tendermint tendermint tendermint
