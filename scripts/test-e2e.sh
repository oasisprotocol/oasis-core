#!/bin/bash -e

WORKDIR=${1:-$(pwd)}

run_dummy_node_default() {
    ${WORKDIR}/target/debug/ekiden-node-dummy \
        --random-beacon-backend dummy \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --time-source-notifier mockrpc \
        --storage-backend dummy \
        &
}

run_dummy_node_storage_dynamodb() {
    ${WORKDIR}/target/debug/ekiden-node-dummy \
        --time-source-notifier mockrpc \
        --random-beacon-backend dummy \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend dynamodb \
        --storage-dynamodb-region us-west-2 \
        --storage-dynamodb-table-name test \
        &
}

run_dummy_node_persistent_state_storage() {
    ${WORKDIR}/target/debug/ekiden-node-dummy \
        --random-beacon-backend dummy \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --time-source-notifier mockrpc \
        --storage-backend dummy \
        --roothash-storage-path "/tmp/dummy_node-state_storage" \
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
        --time-source-notifier system \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --batch-storage immediate_remote \
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

    local db_dir=/tmp/ekiden-test-storage-multilayer-sled-$id
    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --compute-replicas 2 \
        --time-source-notifier system \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --batch-storage multilayer \
        --storage-multilayer-sled-storage-base "$db_dir" \
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

    local db_dir=/tmp/ekiden-test-storage-multilayer-sled-$id
    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --compute-replicas 2 \
        --time-source-notifier system \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --batch-storage multilayer \
        --storage-multilayer-sled-storage-base "$db_dir" \
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
    local restart_dummy_after=$6

    echo -e "\n\e[36;7;1mRUNNING TEST:\e[27m ${description}\e[0m\n"

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    # Start dummy node.
    $dummy_node_runner
    dummy_pid=$!
    sleep 1

    # Handle restarting the dummy node after a delay.
    if [[ -n "${restart_dummy_after}" ]]; then
        (sleep ${restart_dummy_after}; echo -e "\n\n\e[1;7;35m*** RESTARTING DUMMY NODE ***\e[0m\n\n"; kill -9 ${dummy_pid}; ${dummy_node_runner}) &
    fi

    # Run the client. We run the client first so that we test whether it waits for the
    # committee to be elected and connects to the leader.
    ${WORKDIR}/target/debug/${client}-client \
        --mr-enclave $(cat ${WORKDIR}/target/enclave/token.mrenclave) \
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

run_test scenario_basic "e2e-basic" token 1 run_dummy_node_default
run_test scenario_discrepancy_worker "e2e-discrepancy-worker" token 1 run_dummy_node_default
run_test scenario_discrepancy_leader "e2e-discrepancy-leader" token 1 run_dummy_node_default
run_test scenario_fail_worker_after_registration "e2e-fail-worker-after-registration" token 1 run_dummy_node_default
run_test scenario_fail_worker_after_commit "e2e-fail-worker-after-commit" token 1 run_dummy_node_default
run_test scenario_basic "e2e-long" test-long-term 3 run_dummy_node_default
run_test scenario_one_idle "e2e-long-one-idle" test-long-term 3 run_dummy_node_default
if [ -n "$AWS_ACCESS_KEY_ID" -o -e ~/.aws/credentials ]; then
    run_test scenario_basic "e2e-storage-dynamodb" token 1 run_dummy_node_storage_dynamodb
else
    echo >&2 "Skipping DynamoDB test."
fi
if [ -n "$AWS_ACCESS_KEY_ID" -o -e ~/.aws/credentials ]; then
    run_test scenario_multilayer "e2e-storage-multilayer" token 1 run_dummy_node_storage_dynamodb
else
    echo >&2 "Skipping multilayer storage backend test."
fi
run_test scenario_multilayer_remote "e2e-storage-multilayer-remote" token 1 run_dummy_node_default

rm -rf "/tmp/dummy_node-state_storage"
run_test scenario_basic "e2e-basic-recovery" token 2 run_dummy_node_persistent_state_storage 5
