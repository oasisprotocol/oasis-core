#!/bin/bash -e

WORKDIR=${1:-$(pwd)}

# TODO: move all the mock services out ot compute
run_dummy_node_default() {
    ${WORKDIR}/target/debug/ekiden-node-dummy \
        --time-source-notifier ethereum \
        --random-beacon-backend ethereum \
        --beacon-address ${ENV_RandomBeaconMock} \
        --web3-host "ws://127.0.0.1:9545" \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend dummy \
        &
}

run_ethereum() {
    #cd ${WORKDIR}/ethereum && ganache-cli -d -m "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat" -p 9545 &
    cd ${WORKDIR}/ethereum && tail -f /dev/null | truffle develop > /dev/null &
    eval `cd ${WORKDIR}/ethereum && truffle migrate --reset | grep ENV_ | awk '$0="export "$0'`
}

run_compute_node() {
    local id=$1
    shift
    local etherid=$1
    shift
    local extra_args=$*

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --compute-replicas 2 \
        --time-source-notifier ethereum \
        --storage-backend remote \
        --beacon-address ${ENV_RandomBeaconMock} \
        --entity-ethereum-address ${etherid} \
        --web3-host "ws://127.0.0.1:9545" \
        --batch-storage immediate_remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/contract/token.so &
}

run_test() {
    local scenario=$1
    local description=$2
    local client=$3
    local epochs=$4
    local dummy_node_runner=$5

    echo "RUNNING TEST: ${description}"

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    # Start miner.
    ${WORKDIR}/target/debug/ekiden-mockepoch-controller \
            --web3-host "ws://127.0.0.1:9545" \
            --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
            mine &

    # Start dummy node.
    $dummy_node_runner
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
        ${WORKDIR}/target/debug/ekiden-mockepoch-controller \
            --web3-host "ws://127.0.0.1:9545" \
            --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
            set-epoch --epoch $epoch
    done

    # Wait on the client and check its exit status.
    wait ${client_pid}

    # Cleanup.
    echo "Cleaning up."
    pkill -P $$
    wait || true
}

scenario_basic() {
    run_compute_node 1 f17f52151ebef6c7334fad080c5704d77216b732
    sleep 1
    run_compute_node 2 c5fdf4076b8f3a5357c5e395ab970b5b54098fef
    sleep 1
    run_compute_node 3 821aea9a577a9b44299b9c15c88cf3087f3b5544
}

scenario_discrepancy_worker() {
    run_compute_node 1 f17f52151ebef6c7334fad080c5704d77216b732
    sleep 1
    run_compute_node 2 c5fdf4076b8f3a5357c5e395ab970b5b54098fef --test-inject-discrepancy
    sleep 1
    run_compute_node 3 821aea9a577a9b44299b9c15c88cf3087f3b5544
}

scenario_discrepancy_leader() {
    run_compute_node 1 f17f52151ebef6c7334fad080c5704d77216b732
    sleep 1
    run_compute_node 2 c5fdf4076b8f3a5357c5e395ab970b5b54098fef
    sleep 1
    run_compute_node 3 821aea9a577a9b44299b9c15c88cf3087f3b5544 --test-inject-discrepancy
}

run_ethereum
run_test scenario_basic "e2e-basic" token 1 run_dummy_node_default
