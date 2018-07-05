#!/bin/bash -e

WORKDIR=${1:-$(pwd)}
LOGDIR=/tmp/ekiden-benchmarks

run_dummy_node_default() {
    ${WORKDIR}/target/release/ekiden-node-dummy \
        --random-beacon-backend dummy \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --time-source-notifier mockrpc \
        --storage-backend dummy \
        2>${LOGDIR}/dummy.log &
}

run_compute_node() {
    local id=$1
    shift
    local extra_args=$*

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/release/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 20 \
        --max-batch-timeout 100 \
        --compute-replicas 1 \
	--storage-backend persistent \
        --time-source-notifier system \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/contract/token.so 2>${LOGDIR}/compute${id}.log &
}

run_benchmark() {
    local scenario=$1
    local description=$2
    local client=$3
    local epochs=$4
    local dummy_node_runner=$5

    echo "RUNNING BENCHMARK: ${description}"

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    # Re-create log directory.
    rm -rf ${LOGDIR}
    mkdir -p ${LOGDIR}

    # Start dummy node.
    $dummy_node_runner
    sleep 1

    # Start compute nodes.
    $scenario

    # Advance epoch to elect a new committee.
    for epoch in $(seq $epochs); do
        sleep 2
        ${WORKDIR}/target/release/ekiden-node-dummy-controller set-epoch --epoch $epoch
    done

    # Run the client.
    ${WORKDIR}/target/release/${client}-client \
        --mr-enclave $(cat ${WORKDIR}/target/contract/token.mrenclave) \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        --benchmark-threads 50 \
        2>${LOGDIR}/client.log &
    client_pid=$!

    # Wait on the client and check its exit status.
    wait ${client_pid}

    # Cleanup.
    echo "Cleaning up."
    pkill -P $$
    wait || true
}

scenario_basic() {
    run_compute_node 1
    sleep 1
    run_compute_node 2
    sleep 1
}

run_benchmark scenario_basic "e2e-benchmark" benchmark 1 run_dummy_node_default
