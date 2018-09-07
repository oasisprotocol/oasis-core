#!/bin/bash -e

WORKDIR=${1:-$(pwd)}

run_dummy_node_go_default() {
    local datadir=/tmp/ekiden-dummy-data
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level debug \
        --grpc.port 42261 \
        --epochtime.backend mock \
        --beacon.backend insecure \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend memory \
        --datadir ${datadir} \
        &
}

run_dummy_node_go_tm() {
    local datadir=/tmp/ekiden-dummy-data
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level debug \
        --grpc.port 42261 \
        --epochtime.backend tendermint \
        --epochtime.tendermint.interval 30 \
        --beacon.backend tendermint \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend tendermint \
        --roothash.backend tendermint \
        --datadir ${datadir} \
        &
}

run_compute_node() {
    local id=$1
    shift
    local extra_args=$*

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so &
}

run_compute_node_storage_multilayer() {
    local id=$1
    shift
    local extra_args=$*

    local db_dir=/tmp/ekiden-test-storage-multilayer-local-$id
    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --compute-replicas 2 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend multilayer \
        --storage-multilayer-local-storage-base "$db_dir" \
        --storage-multilayer-bottom-backend dynamodb \
        --storage-multilayer-aws-region us-west-2 \
        --storage-multilayer-aws-table-name test \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so &
}

run_compute_node_storage_multilayer_remote() {
    local id=$1
    shift
    local extra_args=$*

    local db_dir=/tmp/ekiden-test-storage-multilayer-local-$id
    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --compute-replicas 2 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend multilayer \
        --storage-multilayer-local-storage-base "$db_dir" \
        --storage-multilayer-bottom-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so &
}

run_test() {
    local scenario=$1
    local description=$2
    local client=$3
    local epochs=$4
    local dummy_node_runner=$5
    local restart_dummy_after=${6:-0}
    local pre_epochs=${7:-0}
    local start_client_first=${8:-0}

    echo -e "\n\e[36;7;1mRUNNING TEST:\e[27m ${description}\e[0m\n"

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    if [[ "${start_client_first}" == 0 ]]; then
        # Start dummy node.
        $dummy_node_runner
        dummy_pid=$!
        sleep 1
    fi

    # Advance epochs before starting any compute nodes.
    if [[ "${pre_epochs}" > 0 ]]; then
        for epoch in $(seq $pre_epochs); do
            sleep 1
            ${WORKDIR}/go/ekiden/ekiden dummy-set-epoch --epoch $epoch
        done
    fi

    # Handle restarting the dummy node after a delay.
    if [[ "${restart_dummy_after}" > 0 ]]; then
        (sleep ${restart_dummy_after}; echo -e "\n\n\e[1;7;35m*** RESTARTING DUMMY NODE ***\e[0m\n\n"; kill -9 ${dummy_pid}; ${dummy_node_runner}) &
    fi

    # Run the client. We run the client first so that we test whether it waits for the
    # committee to be elected and connects to the leader.
    ${WORKDIR}/target/debug/${client}-client \
        --storage-backend remote \
        --mr-enclave $(cat ${WORKDIR}/target/enclave/token.mrenclave) \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 &
    client_pid=$!

    if [[ "${start_client_first}" == 1 ]]; then
        # Start dummy node.
        $dummy_node_runner
        dummy_pid=$!
        sleep 1
    fi

    # Start compute nodes.
    $scenario

    # Advance epoch to elect a new committee.
    let epochs_offset=pre_epochs+1
    let epochs+=pre_epochs
    for epoch in $(seq $epochs_offset $epochs); do
        sleep 2
        ${WORKDIR}/go/ekiden/ekiden dummy-set-epoch --epoch $epoch
    done

    # Wait on the client and check its exit status.
    wait ${client_pid}

    # Cleanup.
    echo "Cleaning up."
    pkill -P $$
    wait || true
}

scenario_basic() {
    run_compute_node 1 --compute-replicas 2
    sleep 1
    run_compute_node 2 --compute-replicas 2
    sleep 1
    run_compute_node 3 --compute-replicas 2
}

scenario_discrepancy_worker() {
    run_compute_node 1 --compute-replicas 2
    sleep 1
    run_compute_node 2 --compute-replicas 2 --test-inject-discrepancy
    sleep 1
    run_compute_node 3 --compute-replicas 2
}

scenario_discrepancy_leader() {
    run_compute_node 1 --compute-replicas 2
    sleep 1
    run_compute_node 2 --compute-replicas 2
    sleep 1
    run_compute_node 3 --compute-replicas 2 --test-inject-discrepancy
}

# Scenario where one node is always idle (not part of computation group).
scenario_one_idle() {
    run_compute_node 1 --compute-replicas 1
    sleep 1
    run_compute_node 2 --compute-replicas 1
    sleep 1
    run_compute_node 3 --compute-replicas 1
}

scenario_multilayer() {
    run_compute_node_storage_multilayer 1
    # Give the first compute node some time to register.
    sleep 1
    run_compute_node_storage_multilayer 2
    sleep 1
    run_compute_node_storage_multilayer 3
}

scenario_multilayer_remote() {
    run_compute_node_storage_multilayer_remote 1
    sleep 1
    run_compute_node_storage_multilayer_remote 2
    sleep 1
    run_compute_node_storage_multilayer_remote 3
}

scenario_fail_worker_after_registration() {
    run_compute_node 1 --compute-replicas 2 --compute-allowed-stragglers 1
    sleep 1
    run_compute_node 2 --compute-replicas 2 --compute-allowed-stragglers 1 --test-fail-after-registration
    sleep 1
    run_compute_node 3 --compute-replicas 2 --compute-allowed-stragglers 1
}

scenario_fail_worker_after_commit() {
    run_compute_node 1 --compute-replicas 2 --compute-allowed-stragglers 1
    sleep 1
    run_compute_node 2 --compute-replicas 2 --compute-allowed-stragglers 1 --test-fail-after-commit
    sleep 1
    run_compute_node 3 --compute-replicas 2 --compute-allowed-stragglers 1
}

# Go node (tendermint backends).
run_test scenario_basic "e2e-basic" token 1 run_dummy_node_go_tm
run_test scenario_discrepancy_worker "e2e-discrepancy-worker" token 1 run_dummy_node_go_tm
run_test scenario_discrepancy_leader "e2e-discrepancy-leader" token 1 run_dummy_node_go_tm
# TODO: Port other E2E tests.

# Alternate starting order (client before dummy node).
run_test scenario_basic "e2e-basic-client-starts-first" token 1 run_dummy_node_go_default 0 0 1
run_test scenario_basic "e2e-basic-client-starts-first-tm" token 1 run_dummy_node_go_tm 0 0 1

# Go node (dummy backends).
#
# Note: e2e-fail-worker-after-[registration,commit] both advance the epoch once
# prior to the tests to ensure that the leader of the committee is not the node
# that will crash (node #2), as the tests do not handle leader failure.
run_test scenario_basic "e2e-basic" token 1 run_dummy_node_go_default
run_test scenario_basic "e2e-basic-pre-epochs" token 1 run_dummy_node_go_default 0 3
run_test scenario_discrepancy_worker "e2e-discrepancy-worker" token 1 run_dummy_node_go_default
run_test scenario_discrepancy_leader "e2e-discrepancy-leader" token 1 run_dummy_node_go_default
run_test scenario_fail_worker_after_registration "e2e-fail-worker-after-registration" token 1 run_dummy_node_go_default 0 1
run_test scenario_fail_worker_after_commit "e2e-fail-worker-after-commit" token 1 run_dummy_node_go_default 0 1
run_test scenario_basic "e2e-long" test-long-term 3 run_dummy_node_go_default
run_test scenario_one_idle "e2e-long-one-idle" test-long-term 3 run_dummy_node_go_default
