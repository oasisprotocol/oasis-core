#!/bin/bash -e

WORKDIR=${1:-$(pwd)}

run_dummy_node_go_dummy() {
    local datadir=/tmp/ekiden-dummy-data
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level debug \
        --grpc.port 42261 \
        --grpc.log.verbose_debug \
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
        --grpc.log.verbose_debug \
        --epochtime.backend tendermint \
        --epochtime.tendermint.interval 30 \
        --beacon.backend tendermint \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend tendermint \
        --roothash.backend tendermint \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.log.debug \
        --datadir ${datadir} \
        &
}

run_dummy_node_go_tm_mock() {
    local datadir=/tmp/ekiden-dummy-data
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level debug \
        --grpc.port 42261 \
        --grpc.log.verbose_debug \
        --epochtime.backend tendermint_mock \
        --beacon.backend insecure \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend tendermint \
        --roothash.backend tendermint \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.log.debug \
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
        --key-manager-cert ${WORKDIR}/tests/keymanager/km.key \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so &
}

run_compute_node_db() {
    local id=$1
    shift
    local extra_args=$*

    # Generate port number.
    let "port=id + 10000"

    RUST_BACKTRACE=1 ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --key-manager-cert ${WORKDIR}/tests/keymanager/km.key \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/test-db-encryption.so &
}

run_compute_node_storage_multilayer_remote() {
    local id=$1
    shift
    local extra_args=$*

    local db_dir=/tmp/ekiden-test-storage-multilayer-local-$id
    rm -rf ${db_dir}

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 1 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend multilayer \
        --storage-multilayer-local-storage-base "$db_dir" \
        --storage-multilayer-bottom-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --key-manager-cert ${WORKDIR}/tests/keymanager/km.key \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so &
}

run_keymanager_node() {
    local extra_args=$*

    ${WORKDIR}/target/debug/ekiden-keymanager-node \
        --enclave ${WORKDIR}/target/enclave/ekiden-keymanager-trusted.so \
        --node-key-pair ${WORKDIR}/tests/keymanager/km.key \
        ${extra_args} &
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
    local test_km=${9:-0}
    local enclave=${10:-token}

    echo -e "\n\e[36;7;1mRUNNING TEST:\e[27m ${description}\e[0m\n"

    # Ensure cleanup on exit.
    trap 'kill -- -0' EXIT

    # Start the key manager before starting anything else.
    run_keymanager_node
    sleep 1

    if [[ "${test_km}" > 0 ]]; then
        # Test the key manager.
        ${WORKDIR}/target/debug/ekiden-keymanager-test-client \
            --mrenclave $(cat ${WORKDIR}/target/enclave/ekiden-keymanager-trusted.mrenclave) \
            --node-key-pair ${WORKDIR}/tests/keymanager/km.key
    fi

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
            ${WORKDIR}/go/ekiden/ekiden dummy set-epoch --epoch $epoch
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
        --mr-enclave $(cat ${WORKDIR}/target/enclave/${enclave}.mrenclave) \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        &
    client_pid=$!

    if [[ "${start_client_first}" == 1 ]]; then
        # Start dummy node.
        $dummy_node_runner
        dummy_pid=$!
        sleep 1
    fi

    # Start compute nodes and wait for them to register.
    $scenario
    ${WORKDIR}/go/ekiden/ekiden dummy wait-nodes --nodes 3

    # Advance epoch to elect a new committee.
    let epochs_offset=pre_epochs+1
    let epochs+=pre_epochs
    for epoch in $(seq $epochs_offset $epochs); do
        sleep 3
        ${WORKDIR}/go/ekiden/ekiden dummy set-epoch --epoch $epoch
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

scenario_basic_db() {
    run_compute_node_db 1 --compute-replicas 2
    sleep 1
    run_compute_node_db 2 --compute-replicas 2
    sleep 1
    run_compute_node_db 3 --compute-replicas 2
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

scenario_multilayer_remote() {
    run_compute_node_storage_multilayer_remote 1 --compute-replicas 2
    sleep 1
    run_compute_node_storage_multilayer_remote 2 --compute-replicas 2
    sleep 1
    run_compute_node_storage_multilayer_remote 3 --compute-replicas 2
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

scenario_leader_skip_commit() {
    local leader_pid

    run_compute_node 1 --compute-replicas 2 --compute-allowed-stragglers 0
    sleep 1
    run_compute_node 2 --compute-replicas 2 --compute-allowed-stragglers 0
    sleep 1
    # Make the leader node skip sending commits for 3 rounds. This test should pass if the
    # roothash backend emits empty blocks for failed rounds, otherwise it may run forever.
    run_compute_node 3 --compute-replicas 2 --compute-allowed-stragglers 0 --test-skip-commit-until-round 3
}

# Tendermint backends.
run_test scenario_basic "e2e-basic-tm-full" token 1 run_dummy_node_go_tm
run_test scenario_basic_db "e2e-basic-tm-db" test-db-encryption 1 run_dummy_node_go_tm_mock 0 0 0 1 test-db-encryption
run_test scenario_basic "e2e-basic-tm" token 1 run_dummy_node_go_tm_mock
run_test scenario_multilayer_remote "e2e-multilayer-remote-tm" token 1 run_dummy_node_go_tm_mock
run_test scenario_discrepancy_worker "e2e-discrepancy-worker-tm" token 1 run_dummy_node_go_tm_mock
run_test scenario_discrepancy_leader "e2e-discrepancy-leader-tm" token 1 run_dummy_node_go_tm_mock
run_test scenario_fail_worker_after_registration "e2e-fail-worker-after-registration-tm" token 1 run_dummy_node_go_tm_mock
run_test scenario_fail_worker_after_commit "e2e-fail-worker-after-commit-tm" token 1 run_dummy_node_go_tm_mock
run_test scenario_basic "e2e-long-tm" test-long-term 2 run_dummy_node_go_tm_mock
run_test scenario_one_idle "e2e-long-one-idle-tm" test-long-term 2 run_dummy_node_go_tm_mock
run_test scenario_leader_skip_commit "e2e-leader-skip-commit-tm" token 1 run_dummy_node_go_tm_mock

# Alternate starting order (client before dummy node).
run_test scenario_basic "e2e-basic-client-starts-first" token 1 run_dummy_node_go_dummy 0 0 1
run_test scenario_basic "e2e-basic-client-starts-first-tm-full" token 1 run_dummy_node_go_tm 0 0 1
run_test scenario_basic "e2e-basic-client-starts-first-tm" token 1 run_dummy_node_go_tm_mock 0 0 1

# Dummy backends.
run_test scenario_basic "e2e-basic" token 1 run_dummy_node_go_dummy
run_test scenario_basic "e2e-basic-pre-epochs" token 1 run_dummy_node_go_dummy 0 3
run_test scenario_discrepancy_worker "e2e-discrepancy-worker" token 1 run_dummy_node_go_dummy
run_test scenario_discrepancy_leader "e2e-discrepancy-leader" token 1 run_dummy_node_go_dummy
run_test scenario_fail_worker_after_registration "e2e-fail-worker-after-registration" token 1 run_dummy_node_go_dummy
run_test scenario_fail_worker_after_commit "e2e-fail-worker-after-commit" token 1 run_dummy_node_go_dummy
run_test scenario_basic "e2e-long" test-long-term 2 run_dummy_node_go_dummy
run_test scenario_one_idle "e2e-long-one-idle" test-long-term 2 run_dummy_node_go_dummy
run_test scenario_leader_skip_commit "e2e-leader-skip-commit" token 1 run_dummy_node_go_dummy
