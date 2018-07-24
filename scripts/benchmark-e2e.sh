#!/bin/bash -e

OUTPUT_FORMAT=${1:-text}
WORKDIR=${2:-$(pwd)}
LOGDIR=/tmp/ekiden-benchmarks

run_dummy_node_storage_dummy() {
    ${WORKDIR}/target/release/ekiden-node-dummy \
        --random-beacon-backend dummy \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --time-source-notifier mockrpc \
        --storage-backend dummy \
        2>${LOGDIR}/dummy.log &
}

run_dummy_node_storage_persistent() {
    local db_dir="/tmp/ekiden-benchmark-storage-persistent"
    rm -rf ${db_dir}

    ${WORKDIR}/target/release/ekiden-node-dummy \
        --random-beacon-backend dummy \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --time-source-notifier mockrpc \
        --storage-backend persistent \
        --storage-path ${db_dir} \
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
        --time-source-notifier system \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --batch-storage immediate_remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so 2>${LOGDIR}/compute${id}.log &
}

run_compute_node_storage_multilayer_remote() {
    local id=$1
    shift
    local extra_args=$*

    local db_dir=/tmp/ekiden-test-storage-multilayer-sled-$id
    rm -rf ${db_dir}

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/release/ekiden-compute \
        --no-persist-identity \
        --max-batch-size 20 \
        --max-batch-timeout 100 \
        --compute-replicas 1 \
        --time-source-notifier system \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --batch-storage multilayer \
        --storage-multilayer-sled-storage-base "$db_dir" \
        --storage-multilayer-bottom-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/token.so 2>${LOGDIR}/compute${id}.log &
}

run_benchmark() {
    local scenario=$1
    local description=$2
    local client=$3
    local epochs=$4
    local dummy_node_runner=$5

    if [[ "${OUTPUT_FORMAT}" == "text" ]]; then
        echo "RUNNING BENCHMARK: ${description}"
    fi

    # Ensure cleanup on exit.
    trap "pkill -P $$ || true" EXIT

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
        --mr-enclave $(cat ${WORKDIR}/target/enclave/token.mrenclave) \
        --test-contract-id 0000000000000000000000000000000000000000000000000000000000000000 \
        --benchmark-threads 50 \
        --output-format ${OUTPUT_FORMAT} \
        --output-title-prefix "${description}" \
        2>${LOGDIR}/client.log &
    client_pid=$!

    # Wait on the client and check its exit status.
    wait ${client_pid}

    # Cleanup.
    if [[ "${OUTPUT_FORMAT}" == "text" ]]; then
        echo "Cleaning up."
    fi
    pkill -P $$
    wait || true
}

scenario_basic() {
    run_compute_node 1
    sleep 1
    run_compute_node 2
    sleep 1
}

scenario_multilayer_remote() {
    run_compute_node_storage_multilayer_remote 1
    sleep 1
    run_compute_node_storage_multilayer_remote 2
    sleep 1
}

run_benchmark scenario_basic "e2e-benchmark" benchmark 1 run_dummy_node_storage_dummy
run_benchmark scenario_basic "e2e-benchmark-persistent" benchmark 1 run_dummy_node_storage_persistent
run_benchmark scenario_multilayer_remote "e2e-benchmark-multilayer-remote" benchmark 1 run_dummy_node_storage_dummy
