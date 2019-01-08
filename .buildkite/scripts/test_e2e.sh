#!/bin/bash

############################################################
# This script tests the Ekiden rust project.
#
# Usage:
# test_e2e.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
source .buildkite/scripts/common_e2e.sh
source .buildkite/rust/common.sh

# Working directory.
WORKDIR=${1:-$(pwd)}

# Global test counter used for parallelizing jobs.
E2E_TEST_COUNTER=0

##############################
# Run a specific test scenario
##############################
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
    local on_success_hook=${11:-""}

    # Check if we should run this test.
    local test_index=$E2E_TEST_COUNTER
    let E2E_TEST_COUNTER+=1 1

    if [[ -n ${BUILDKITE_PARALLEL_JOB+x} ]]; then
        let test_index%=BUILDKITE_PARALLEL_JOB_COUNT 1

        if [[ $BUILDKITE_PARALLEL_JOB != $test_index ]]; then
            echo "Skipping test '${description}' (assigned to different parallel build)."
            return
        fi
    fi

    echo -e "\n\e[36;7;1mRUNNING TEST:\e[27m ${description}\e[0m\n"

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
            ${WORKDIR}/go/ekiden/ekiden debug dummy set-epoch --epoch $epoch
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
    ${WORKDIR}/go/ekiden/ekiden debug dummy wait-nodes --nodes 3

    # Advance epoch to elect a new committee.
    let epochs_offset=pre_epochs+1
    let epochs+=pre_epochs
    for epoch in $(seq $epochs_offset $epochs); do
        sleep 3
        ${WORKDIR}/go/ekiden/ekiden debug dummy set-epoch --epoch $epoch
    done

    # Wait on the client and check its exit status.
    wait ${client_pid}

    if [[ "$on_success_hook" != "" ]]; then
        $on_success_hook
    fi

    # Cleanup.
    cleanup
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

scenario_kill_worker() {
    run_compute_node 1 --compute-replicas 2
    sleep 1
    run_compute_node 2 --compute-replicas 2
    sleep 1
    run_compute_node 3 --compute-replicas 2

    # Wait for all nodes to register.
    ${WORKDIR}/go/ekiden/ekiden debug dummy wait-nodes --nodes 3

    # Kill newest worker. The compute node should restart it.
    pkill -9 --newest worker
    sleep 1
}

scenario_logger() {
    run_compute_node_logger 1
    sleep 1
    run_compute_node_logger 2
    sleep 1
    run_compute_node_logger 3
}

check_logger_logs() {
    log_files=()
    for id in 1 2 3; do
        log_files+="/tmp/ekiden-test-logger-$id "
    done

    # test-logger-client sends five distinct messages to five distinct log levels.
    # Check, if they are correctly reported by the enclave and then by pretty_env_logger.
    grep "ERROR" $log_files | grep "<enclave>::test_logger" | grep "hello_error" >/dev/null
    grep "WARN" $log_files | grep "<enclave>::test_logger" | grep "hello_warn" >/dev/null
    grep "INFO" $log_files | grep "<enclave>::test_logger" | grep "hello_info" >/dev/null
    grep "DEBUG" $log_files | grep "<enclave>::test_logger" | grep "hello_debug" >/dev/null
    grep "TRACE" $log_files | grep "<enclave>::test_logger" | grep "hello_trace" >/dev/null
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

run_test scenario_basic "e2e-basic-tm-full-distributed" token 1 run_committee_go_tm

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
run_test scenario_kill_worker "e2e-kill-worker" token 1 run_dummy_node_go_dummy

# Logging.
run_test scenario_logger "e2e-logging" test-logger 1 run_dummy_node_go_dummy 0 0 0 1 test-logger check_logger_logs
