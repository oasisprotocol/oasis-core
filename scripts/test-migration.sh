#!/bin/bash -e

WORKDIR=${1:-$(pwd)}

CONTRACT_ID=0000000000000000000000000000000000000000000000000000000000000000

test_migration() {
    local epochtime_backend=$1
    local roothash_backend=$2

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    local datadir=/tmp/ekiden-dummy-data

    # Start the first dummy network.
    rm -rf "$datadir"
    "$WORKDIR/go/ekiden/ekiden" \
        --log.level debug \
        --grpc.port 42261 \
        --epochtime.backend "$epochtime_backend" \
        --beacon.backend insecure \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend memory \
        --roothash.backend "$roothash_backend" \
        --datadir "$datadir" \
        &
    local first_dummy_pid=$(jobs -p +)

    sleep 1

    "$WORKDIR/target/debug/ekiden-compute" \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10001 \
        --disable-key-manager \
        --test-contract-id "$CONTRACT_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local first_compute1_pid=$(jobs -p +)

    "$WORKDIR/target/debug/ekiden-compute" \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10002 \
        --disable-key-manager \
        --test-contract-id "$CONTRACT_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local first_compute2_pid=$(jobs -p +)

    sleep 1

    "$WORKDIR/go/ekiden/ekiden" dummy set-epoch --epoch 1

    sleep 1

    # Start long term client, which has a 10-second wait.
    "$WORKDIR/target/debug/test-long-term-client" \
        --storage-backend remote \
        --mr-enclave "$(cat "$WORKDIR/target/enclave/token.mrenclave")" \
        --test-contract-id "$CONTRACT_ID" \
        &
    local client_pid=$(jobs -p +)

    sleep 2
    # 2 sec

    # Stop the network.
    kill "$first_compute1_pid" "$first_compute2_pid"
    wait "$first_compute1_pid" "$first_compute2_pid" || true

    # Export.
    "$WORKDIR/scripts/storage/export.py" >/tmp/ekiden-test-storage.dat
    "$WORKDIR/scripts/roothash/export.py" "$CONTRACT_ID" >/tmp/ekiden-test-roothash.dat

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
        --beacon.backend insecure \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend memory \
        --roothash.backend "$roothash_backend" \
        --roothash.genesis-blocks /tmp/ekiden-test-roothash.dat \
        --datadir "$datadir" \
        &
    local second_dummy_pid=$(jobs -p +)

    sleep 1
    # 4 sec

    # Import.
    "$WORKDIR/scripts/storage/import.py" --current-epoch 1 </tmp/ekiden-test-storage.dat

    # Finish starting the second network.
    "$WORKDIR/target/debug/ekiden-compute" \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10001 \
        --disable-key-manager \
        --test-contract-id "$CONTRACT_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local second_compute1_pid=$(jobs -p +)

    "$WORKDIR/target/debug/ekiden-compute" \
        --no-persist-identity \
        --max-batch-size 1 \
        --storage-backend remote \
        --port 10002 \
        --disable-key-manager \
        --test-contract-id "$CONTRACT_ID" \
        "$WORKDIR/target/enclave/token.so" \
        &
    local second_compute2_pid=$(jobs -p +)
    
    sleep 1
    # 5 sec

    "$WORKDIR/go/ekiden/ekiden" dummy set-epoch --epoch 2


    # Wait on the client and check its exit status.
    wait "$client_pid"

    # Cleanup.
    echo "Cleaning up."
    pkill -P $$
    wait || true
}

set -x
test_migration mock memory
