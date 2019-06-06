#!/bin/bash -e

OUTPUT_FORMAT=${1:-text}
WORKDIR=${2:-$(pwd)}
LOGDIR=/tmp/ekiden-benchmarks

run_dummy_node_storage_dummy() {
    local datadir=/tmp/ekiden-benchmark-dummy-data
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level info \
        --grpc.port 42261 \
        --epochtime.backend mock \
        --beacon.backend insecure \
        --storage.backend memory \
        --scheduler.backend trivial \
        --registry.backend memory \
        --datadir ${datadir} \
        >${LOGDIR}/dummy.log &
}

run_dummy_node_storage_persistent() {
    local datadir=/tmp/ekiden-benchmark-dummy-data
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level info \
        --grpc.port 42261 \
        --epochtime.backend mock \
        --beacon.backend insecure \
        --storage.backend leveldb \
        --scheduler.backend trivial \
        --registry.backend memory \
        --datadir ${datadir} \
        >${LOGDIR}/dummy.log &
}

run_dummy_node_tendermint() {
    local datadir=/tmp/ekiden-benchmark-tendermint
    rm -rf ${datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level info \
        --grpc.port 42261 \
        --epochtime.backend tendermint_mock \
        --beacon.backend insecure \
        --storage.backend memory \
        --scheduler.backend tendermint \
        --registry.backend tendermint \
        --roothash.backend tendermint \
        --tendermint.consensus.timeout_commit 250ms \
        --datadir ${datadir} \
        >${LOGDIR}/dummy.log &
}

run_compute_node() {
    local id=$1
    shift
    local extra_args=$*

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/release/ekiden-compute \
        --worker-path ${WORKDIR}/target/release/ekiden-worker \
        --no-persist-identity \
        --max-batch-size 20 \
        --max-batch-timeout 100 \
        --compute-replicas 1 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --disable-key-manager \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/simple-keyvalue.so 2>${LOGDIR}/compute${id}.log &
}

run_compute_node_storage_multilayer_remote() {
    local id=$1
    shift
    local extra_args=$*

    local db_dir=/tmp/ekiden-test-storage-multilayer-local-$id
    rm -rf ${db_dir}

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/release/ekiden-compute \
        --worker-path ${WORKDIR}/target/release/ekiden-worker \
        --no-persist-identity \
        --max-batch-size 20 \
        --max-batch-timeout 100 \
        --compute-replicas 1 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend multilayer \
        --storage-multilayer-local-storage-base "$db_dir" \
        --storage-multilayer-bottom-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --disable-key-manager \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/simple-keyvalue.so 2>${LOGDIR}/compute${id}.log &
}

run_benchmark() {
    local scenario=$1
    local description=$2
    local client=$3
    local epochs=$4
    local dummy_node_runner=$5
    local rq_per_thread=${6:-1000}

    if [[ "${OUTPUT_FORMAT}" == "text" ]]; then
        echo -e "\n\e[36;7;1mRUNNING BENCHMARK:\e[27m ${description}\e[0m\n"
    fi

    # Ensure cleanup on exit.
    trap "pkill -P $$ || true" EXIT

    # Re-create log directory.
    rm -rf ${LOGDIR}
    mkdir -p ${LOGDIR}

    # Start dummy node.
    $dummy_node_runner
    sleep 1

    # Start compute nodes and wait for them to register.
    $scenario
    ${WORKDIR}/go/ekiden/ekiden debug dummy wait-nodes --nodes 2

    # Advance epoch to elect a new committee.
    for epoch in $(seq $epochs); do
        sleep 2
        ${WORKDIR}/go/ekiden/ekiden debug dummy set-epoch --epoch $epoch
    done

    # Run the client.
    RUST_LOG=info ${WORKDIR}/target/release/${client}-client \
        --storage-backend remote \
        --mr-enclave $(cat ${WORKDIR}/target/enclave/simple-keyvalue.mrenclave) \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        --benchmark-threads 50 \
        --benchmark-runs ${rq_per_thread} \
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
run_benchmark scenario_basic "e2e-benchmark-tendermint" benchmark 1 run_dummy_node_tendermint 100
run_benchmark scenario_multilayer_remote "e2e-benchmark-multilayer-remote" benchmark 1 run_dummy_node_storage_dummy
