#!/bin/bash -e

WORKDIR=${1:-$(pwd)}

run_compute_node() {
    local id=$1
    shift
    local extra_args=$*

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --compute-replicas 2 \
        --port ${port} \
        --key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/contract/token.so &
}

run_test() {
    local scenario=$1
    local description=$2
    local client=$3
    local epochs=$4

    echo "RUNNING TEST: ${description}"

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    # Start dummy node.
    ${WORKDIR}/target/debug/ekiden-node-dummy --time-source mockrpc &
    sleep 1

    # Run the client. We run the client first so that we test whether it waits for the
    # committee to be elected and connects to the leader.
    ${WORKDIR}/target/debug/${client}-client \
        --mr-enclave $(cat ${WORKDIR}/target/contract/token.mrenclave) \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 &
    client_pid=$!

    # Start compute nodes.
    $scenario

    # Advance epoch to elect a new committee.
    for epoch in $(seq $epochs); do
        sleep 2
        ${WORKDIR}/target/debug/ekiden-node-dummy-controller set-epoch --epoch $epoch
    done

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
    run_compute_node 3
}

scenario_discrepancy_worker() {
    run_compute_node 1
    sleep 1
    run_compute_node 2 --test-inject-discrepancy
    sleep 1
    run_compute_node 3
}

scenario_discrepancy_leader() {
    run_compute_node 1
    sleep 1
    run_compute_node 2
    sleep 1
    run_compute_node 3 --test-inject-discrepancy
}

run_test scenario_basic "e2e-basic" token 1
run_test scenario_discrepancy_worker "e2e-discrepancy-worker" token 1
run_test scenario_discrepancy_leader "e2e-discrepancy-leader" token 1
run_test scenario_basic "e2e-long" test-long-term 3
