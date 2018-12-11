################################
# Common functions for E2E tests
################################

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

    local cache_dir=/tmp/ekiden-test-worker-cache-$id
    rm -rf ${cache_dir}

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir ${cache_dir} \
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

    local cache_dir=/tmp/ekiden-test-worker-cache-$id
    rm -rf ${cache_dir}

    # Generate port number.
    let "port=id + 10000"

    RUST_BACKTRACE=1 ${WORKDIR}/target/debug/ekiden-compute \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir ${cache_dir} \
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

run_compute_node_logger() {
    local id=$1
    shift
    local extra_args=$*

    local log_path=/tmp/ekiden-test-logger-$id
    local cache_dir=/tmp/ekiden-test-worker-cache-$id
    rm -rf ${cache_dir}

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir ${cache_dir} \
        --no-persist-identity \
        --max-batch-size 1 \
        --entity-ethereum-address 627306090abab3a6e1400e9345bc60c78a8bef57 \
        --storage-backend remote \
        --port ${port} \
        --node-key-pair ${WORKDIR}/tests/committee_3_nodes/node${id}.key \
        --key-manager-cert ${WORKDIR}/tests/keymanager/km.key \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${extra_args} \
        ${WORKDIR}/target/enclave/test-logger.so &>$log_path &
}

run_compute_node_storage_multilayer_remote() {
    local id=$1
    shift
    local extra_args=$*

    local db_dir=/tmp/ekiden-test-storage-multilayer-local-$id
    rm -rf ${db_dir}

    local cache_dir=/tmp/ekiden-test-worker-cache-$id
    rm -rf ${cache_dir}

    # Generate port number.
    let "port=id + 10000"

    ${WORKDIR}/target/debug/ekiden-compute \
        --worker-path ${WORKDIR}/target/debug/ekiden-worker \
        --worker-cache-dir ${cache_dir} \
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

    local db_dir=/tmp/ekiden-test-keymanager
    rm -rf ${db_dir}

    ${WORKDIR}/target/debug/ekiden-keymanager-node \
        --enclave ${WORKDIR}/target/enclave/ekiden-keymanager-trusted.so \
        --node-key-pair ${WORKDIR}/tests/keymanager/km.key \
        --storage-backend dummy \
        --storage-path ${db_dir} \
        ${extra_args} &
}
