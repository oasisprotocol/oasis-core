#!/bin/bash

############################################################
# This script tests the Ekiden project.
#
# Usage:
# test_e2e.sh [-w <workdir>] [-t <test-name>]
############################################################

# Defaults.
WORKDIR=$(pwd)
TEST_FILTER=""

#########################
# Process test arguments.
#########################
while getopts 'f:t:' arg
do
    case ${arg} in
        w) WORKDIR=${OPTARG};;
        t) TEST_FILTER=${OPTARG};;
        *)
            echo "Usage: $0 [-w <workdir>] [-t <test-name>]"
            exit 1
    esac
done

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
source .buildkite/scripts/common_e2e.sh
source .buildkite/rust/common.sh

###################
# Test definitions.
###################
scenario_basic() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 2 storage + key manager + 3 validator.
    wait_nodes 9

    # Advance epoch to elect a new committee.
    set_epoch 1
}

scenario_compute_discrepancy() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime} \
        --worker.compute.byzantine.inject_discrepancies
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 2 storage + key manager + 3 validator.
    wait_nodes 9

    # Advance epoch to elect a new committee.
    set_epoch 1
}

assert_compute_discrepancy_scenario_works() {
    assert_no_panics
    assert_no_round_timeouts
    assert_compute_discrepancies
    assert_no_merge_discrepancies
}

scenario_merge_discrepancy() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime} \
        --worker.merge.byzantine.inject_discrepancies
    run_compute_node 3 ${runtime}

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 2 storage + key manager + 3 validator.
    wait_nodes 9

    # Advance epoch to elect a new committee.
    set_epoch 1
}

assert_merge_discrepancy_scenario_works() {
    assert_no_panics
    assert_no_round_timeouts
    assert_no_compute_discrepancies
    assert_merge_discrepancies
}

scenario_storage_sync() {
    local runtime=simple-keyvalue
    local client=simple-keyvalue

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2 extra_args="--worker.debug.storage.ignore_apply"

    # Wait for all nodes to start: 3 compute + 2 storage + key manager.
    wait_nodes 6

    # Advance epoch to elect a new committee.
    set_epoch 1

    # Wait for the client to exit without waiting on it.
    while kill -0 ${EKIDEN_CLIENT_PID}; do
        sleep 5
    done

    local log_file=${EKIDEN_COMMITTEE_DIR}/client-storage-debug.log
    ${EKIDEN_NODE} debug storage check-roots \
        --datadir ${EKIDEN_COMMITTEE_DIR} \
        --log.level debug \
        --log.file ${log_file} \
        --storage.debug.client.address "unix:${EKIDEN_LAST_NODE_DATA_DIR}/internal.sock" \
        --address "unix:${EKIDEN_LAST_NODE_DATA_DIR}/internal.sock" \
        ${EKIDEN_RUNTIME_ID}
}

scenario_byzantine_compute_honest() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Use fixed identity to ensure deterministic committees.
    mkdir -p ${EKIDEN_COMMITTEE_DIR}/byzantine
    chmod 700 ${EKIDEN_COMMITTEE_DIR}/byzantine
    cp ${WORKDIR}/tests/identities/byzantine.pem ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem
    chmod 600 ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem

    ${EKIDEN_NODE} debug byzantine compute-honest \
        --log.level debug \
        --log.format JSON \
        --genesis.file ${EKIDEN_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:13004 \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --worker.p2p.port 12004 \
        --worker.registration.entity ${EKIDEN_ENTITY_DESCRIPTOR} \
        --worker.registration.private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --datadir ${EKIDEN_COMMITTEE_DIR}/byzantine \
        --debug.allow_test_keys \
        ${EKIDEN_TEE_HARDWARE:+--fake_sgx} \
        2>&1 | sed "s/^/[byzantine] /" &

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 1 byzantine + 2 storage + key manager + 3 validator.
    wait_nodes 10

    # Advance epoch to elect a new committee.
    set_epoch 1
}

scenario_byzantine_compute_wrong() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Use fixed identity to ensure deterministic committees.
    mkdir -p ${EKIDEN_COMMITTEE_DIR}/byzantine
    chmod 700 ${EKIDEN_COMMITTEE_DIR}/byzantine
    cp ${WORKDIR}/tests/identities/byzantine.pem ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem
    chmod 600 ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem

    ${EKIDEN_NODE} debug byzantine compute-wrong \
        --log.level debug \
        --log.format JSON \
        --genesis.file ${EKIDEN_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:13004 \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --worker.p2p.port 12004 \
        --worker.registration.entity ${EKIDEN_ENTITY_DESCRIPTOR} \
        --worker.registration.private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --datadir ${EKIDEN_COMMITTEE_DIR}/byzantine \
        --debug.allow_test_keys \
        ${EKIDEN_TEE_HARDWARE:+--fake_sgx} \
        2>&1 | sed "s/^/[byzantine] /" &

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 1 byzantine + 2 storage + key manager + 3 validator.
    wait_nodes 10

    # Advance epoch to elect a new committee.
    set_epoch 1
}

scenario_byzantine_compute_straggler() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Use fixed identity to ensure deterministic committees.
    mkdir -p ${EKIDEN_COMMITTEE_DIR}/byzantine
    chmod 700 ${EKIDEN_COMMITTEE_DIR}/byzantine
    cp ${WORKDIR}/tests/identities/byzantine.pem ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem
    chmod 600 ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem

    ${EKIDEN_NODE} debug byzantine compute-straggler \
        --log.level debug \
        --log.format JSON \
        --genesis.file ${EKIDEN_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:13004 \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --worker.p2p.port 12004 \
        --worker.registration.entity ${EKIDEN_ENTITY_DESCRIPTOR} \
        --worker.registration.private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --datadir ${EKIDEN_COMMITTEE_DIR}/byzantine \
        --debug.allow_test_keys \
        ${EKIDEN_TEE_HARDWARE:+--fake_sgx} \
        --mock_epochtime \
        2>&1 | sed "s/^/[byzantine] /" &

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 1 byzantine + 2 storage + key manager + 3 validator.
    wait_nodes 10

    # Advance epoch to elect a new committee.
    set_epoch 1
}

assert_compute_straggler_scenario_works() {
    assert_no_panics
    assert_round_timeouts
    assert_compute_discrepancies
    assert_no_merge_discrepancies
}

scenario_byzantine_merge_honest() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Use fixed identity to ensure deterministic committees.
    mkdir -p ${EKIDEN_COMMITTEE_DIR}/byzantine
    chmod 700 ${EKIDEN_COMMITTEE_DIR}/byzantine
    cp ${WORKDIR}/tests/identities/byzantine.pem ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem
    chmod 600 ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem

    ${EKIDEN_NODE} debug byzantine merge-honest \
        --log.level debug \
        --log.format JSON \
        --genesis.file ${EKIDEN_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:13004 \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --worker.p2p.port 12004 \
        --worker.registration.entity ${EKIDEN_ENTITY_DESCRIPTOR} \
        --worker.registration.private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --datadir ${EKIDEN_COMMITTEE_DIR}/byzantine \
        --debug.allow_test_keys \
        2>&1 | sed "s/^/[byzantine] /" &

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 1 byzantine + 2 storage + key manager + 3 validator.
    wait_nodes 10

    # Advance epoch to elect a new committee.
    set_epoch 1
}

assert_merge_straggler_scenario_works() {
    assert_no_panics
    assert_round_timeouts
    assert_no_compute_discrepancies
    assert_merge_discrepancies
}

scenario_byzantine_merge_wrong() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Use fixed identity to ensure deterministic committees.
    mkdir -p ${EKIDEN_COMMITTEE_DIR}/byzantine
    chmod 700 ${EKIDEN_COMMITTEE_DIR}/byzantine
    cp ${WORKDIR}/tests/identities/byzantine.pem ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem
    chmod 600 ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem

    ${EKIDEN_NODE} debug byzantine merge-wrong \
        --log.level debug \
        --log.format JSON \
        --genesis.file ${EKIDEN_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:13004 \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --worker.p2p.port 12004 \
        --worker.registration.entity ${EKIDEN_ENTITY_DESCRIPTOR} \
        --worker.registration.private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --datadir ${EKIDEN_COMMITTEE_DIR}/byzantine \
        --debug.allow_test_keys \
        2>&1 | sed "s/^/[byzantine] /" &

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 1 byzantine + 2 storage + key manager + 3 validator.
    wait_nodes 10

    # Advance epoch to elect a new committee.
    set_epoch 1
}

scenario_byzantine_merge_straggler() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Use fixed identity to ensure deterministic committees.
    mkdir -p ${EKIDEN_COMMITTEE_DIR}/byzantine
    chmod 700 ${EKIDEN_COMMITTEE_DIR}/byzantine
    cp ${WORKDIR}/tests/identities/byzantine.pem ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem
    chmod 600 ${EKIDEN_COMMITTEE_DIR}/byzantine/identity.pem

    ${EKIDEN_NODE} debug byzantine merge-straggler \
        --log.level debug \
        --log.format JSON \
        --genesis.file ${EKIDEN_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:13004 \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --worker.p2p.port 12004 \
        --worker.registration.entity ${EKIDEN_ENTITY_DESCRIPTOR} \
        --worker.registration.private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --datadir ${EKIDEN_COMMITTEE_DIR}/byzantine \
        --debug.allow_test_keys \
        2>&1 | sed "s/^/[byzantine] /" &

    # Initialize storage nodes.
    run_storage_node 1
    run_storage_node 2

    # Wait for all nodes to start: 3 compute + 1 byzantine + 2 storage + key manager + 3 validator.
    wait_nodes 10

    # Advance epoch to elect a new committee.
    set_epoch 1
}

run_client_km_restart() {
    local runtime=$1
    local client=$2

    (
        trap_add 'cleanup' EXIT

        # Run client on first key.
        run_basic_client ${runtime} ${client} --key key1
        wait ${EKIDEN_CLIENT_PID}

        # Restart the key manager.
        pkill --echo --full --signal 9 keymanager.runtime
        sleep 1
        # Keep the data directory.
        run_keymanager_node 1
        sleep 3
        # Wait for the key manager node to be synced.
        ${EKIDEN_NODE} debug client wait-sync \
            --address unix:${EKIDEN_COMMITTEE_DIR}/key-manager/internal.sock
        sleep 10 # HACK: KM initialization involves tendermint

        # Run client on a different key so that it will require another
        # trip to the key manager.
        run_basic_client ${runtime} ${client} --key key2
        wait ${EKIDEN_CLIENT_PID}
    ) &
    EKIDEN_CLIENT_PID=$!
}

#############
# Test suite.
#
# Arguments:
#    backend_name - name of the backend to use in test name
#    backend_runner - function that will prepare and run the backend services
#############
test_suite() {
    local backend_name=$1
    local backend_runner=$2

    # Basic scenario using the simple-keyvalue runtime and client.
    run_test \
        scenario=scenario_basic \
        name="e2e-${backend_name}-basic-full" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue

    # Database encryption test.
    run_test \
        scenario=scenario_basic \
        name="e2e-${backend_name}-basic-enc" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-enc

    # Database encryption test with restarting key manager.
    run_test \
        scenario=scenario_basic \
        name="e2e-${backend_name}-km-restart" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-enc \
        client_runner=run_client_km_restart

    # Discrepancy scenarios.
    # NOTE: This scenario currently fails on SGX due to the way discrepancy
    # injection is currently implemented.
    # For more details, see:
    # https://github.com/oasislabs/ekiden/issues/1730.
    if [[ ${EKIDEN_TEE_HARDWARE} != "intel-sgx" ]]; then
        run_test \
            scenario=scenario_compute_discrepancy \
            name="e2e-${backend_name}-compute-discrepancy" \
            backend_runner=$backend_runner \
            runtime=simple-keyvalue \
            client=simple-keyvalue \
            on_success_hook=assert_compute_discrepancy_scenario_works \
            beacon_deterministic=1
    fi

    run_test \
        scenario=scenario_merge_discrepancy \
        name="e2e-${backend_name}-merge-discrepancy" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue \
        on_success_hook=assert_merge_discrepancy_scenario_works \
        beacon_deterministic=1

    # Storage node syncing scenario.
    run_test \
        scenario=scenario_storage_sync \
        name="e2e-${backend_name}-storage-sync" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue

    run_test \
        scenario=scenario_byzantine_compute_honest \
        name="e2e-${backend_name}-byzantine-compute-honest" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-ops \
        client_extra_args="set hello_key hello_value" \
        beacon_deterministic=1

    run_test \
        scenario=scenario_byzantine_compute_wrong \
        name="e2e-${backend_name}-byzantine-compute-wrong" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-ops \
        client_extra_args="set hello_key hello_value" \
        on_success_hook=assert_compute_discrepancy_scenario_works \
        beacon_deterministic=1

    run_test \
        scenario=scenario_byzantine_compute_straggler \
        name="e2e-${backend_name}-byzantine-compute-straggler" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-ops \
        client_extra_args="set hello_key hello_value" \
        on_success_hook=assert_compute_straggler_scenario_works \
        epochtime_backend=tendermint_mock \
        beacon_deterministic=1

    run_test \
        scenario=scenario_byzantine_merge_honest \
        name="e2e-${backend_name}-byzantine-merge-honest" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-ops \
        client_extra_args="set hello_key hello_value" \
        beacon_deterministic=1

    run_test \
        scenario=scenario_byzantine_merge_wrong \
        name="e2e-${backend_name}-byzantine-merge-wrong" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-ops \
        client_extra_args="set hello_key hello_value" \
        on_success_hook=assert_merge_discrepancy_scenario_works \
        beacon_deterministic=1

    run_test \
        scenario=scenario_byzantine_merge_straggler \
        name="e2e-${backend_name}-byzantine-merge-straggler" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-ops \
        client_extra_args="set hello_key hello_value" \
        on_success_hook=assert_merge_straggler_scenario_works \
        beacon_deterministic=1
}

##########################################
# Multiple validators tendermint backends.
##########################################
test_suite tm run_backend_tendermint_committee
