################################
# Common functions for E2E tests
################################

# Temporary test base directory.
TEST_BASE_DIR=$(mktemp -d --tmpdir ekiden-e2e-XXXXXXXXXX)

# Path to Ekiden root.
EKIDEN_ROOT_PATH=${EKIDEN_ROOT_PATH:-${WORKDIR}}
# Path to the Ekiden node.
EKIDEN_NODE=${EKIDEN_NODE:-${EKIDEN_ROOT_PATH}/go/ekiden/ekiden}
# Path to the runtime loader.
EKIDEN_RUNTIME_LOADER=${EKIDEN_RUNTIME_LOADER:-${EKIDEN_ROOT_PATH}/target/debug/ekiden-runtime-loader}
# TEE hardware (optional).
EKIDEN_TEE_HARDWARE=${EKIDEN_TEE_HARDWARE:-""}

# Run a Tendermint validator committee and a storage node.
#
# Sets:
#   EKIDEN_COMMITTEE_DIR
#   EKIDEN_TM_GENESIS_FILE
#   EKIDEN_STORAGE_PORT
#   EKIDEN_IAS_PROXY_PORT
#   EKIDEN_EPOCHTIME_BACKEND
#   EKIDEN_VALIDATOR_SOCKET
#   EKIDEN_ENTITY_PRIVATE_KEY
#
# Optional named arguments:
#
#   epochtime_backend - epochtime backend (default: tendermint)
#   id - commitee identifier (default: 1)
#   replica_group_size - runtime replica group size (default: 2)
#   replica_group_backup_size - runtime replica group backup size (default: 1)
#   start_storage - start the storage node
#
# Any additional arguments are passed to the validator Go node and
# all compute nodes.
run_backend_tendermint_committee() {
    # Optional arguments with default values.
    local epochtime_backend="tendermint"
    local id=1
    local replica_group_size=2
    local replica_group_backup_size=1
    local start_storage=true
    local roothash_genesis_blocks=""
    local nodes=3
    # Load named arguments that override defaults.
    local "${@}"

    local committee_dir=${TEST_BASE_DIR}/committee-${id}
    local base_datadir=${committee_dir}/committee-data
    local validator_files=""

    # Provision the validators.
    for idx in $(seq 1 $nodes); do
        local datadir=${base_datadir}-${idx}
        rm -rf ${datadir}

        let port=(idx-1)+26656
        ${EKIDEN_NODE} \
            tendermint provision_validator \
            --datadir ${datadir} \
            --node_addr 127.0.0.1:${port} \
            --node_name ekiden-committee-node-${idx} \
            --validator_file ${datadir}/validator.json
        validator_files="$validator_files --validator=${datadir}/validator.json"
    done

    # Provision the entity for all the workers.
    local entity_dir=${committee_dir}/entity
    rm -Rf ${entity_dir}

    ${EKIDEN_NODE} \
        registry entity init \
        --datadir ${entity_dir}

    # Provision the runtime.
    ${EKIDEN_NODE} \
        registry runtime init_genesis \
        --runtime.id 0000000000000000000000000000000000000000000000000000000000000000 \
        --runtime.replica_group_size ${replica_group_size} \
        --runtime.replica_group_backup_size ${replica_group_backup_size} \
        ${EKIDEN_TEE_HARDWARE:+--runtime.tee_hardware ${EKIDEN_TEE_HARDWARE}} \
        --entity ${entity_dir} \
        --datadir ${entity_dir}

    # Create the genesis document.
    local genesis_file=${committee_dir}/genesis.json
    rm -Rf ${genesis_file}

    ${EKIDEN_NODE} \
        tendermint init_genesis \
        --genesis_file ${genesis_file} \
        --entity ${entity_dir}/entity_genesis.json \
        --runtime ${entity_dir}/runtime_genesis.json \
        ${roothash_genesis_blocks:+--roothash ${roothash_genesis_blocks}} \
        ${validator_files}

    # Run the storage node.
    local storage_datadir=${committee_dir}/storage
    local storage_port=60000

    if [ "$start_storage" = true ]; then
        rm -Rf ${storage_datadir}

        ${EKIDEN_NODE} \
            storage node \
            --datadir ${storage_datadir} \
            --grpc.port ${storage_port} \
            --log.file ${committee_dir}/storage.log \
            &
    fi

    # Run the IAS proxy if needed.
    local ias_proxy_port=9001

    if [[ "${EKIDEN_TEE_HARDWARE}" == "intel-sgx" ]]; then
        # TODO: Ensure that IAS credentials are configured.
        ${EKIDEN_NODE} \
            ias proxy \
            --auth_cert ${EKIDEN_IAS_CERT} \
            --auth_cert_ca ${EKIDEN_IAS_CERT} \
            --auth_key ${EKIDEN_IAS_KEY} \
            --spid ${EKIDEN_IAS_SPID} \
            --metrics.mode none \
            --log.level debug \
            --log.file ${committee_dir}/ias-proxy.log \
            &
    fi

    # Export some variables so compute workers can find them.
    EKIDEN_COMMITTEE_DIR=${committee_dir}
    EKIDEN_VALIDATOR_SOCKET=${base_datadir}-1/internal.sock
    EKIDEN_STORAGE_PORT=${storage_port}
    EKIDEN_IAS_PROXY_PORT=${ias_proxy_port}
    EKIDEN_TM_GENESIS_FILE=${genesis_file}
    EKIDEN_EPOCHTIME_BACKEND=${epochtime_backend}
    EKIDEN_ENTITY_PRIVATE_KEY=${entity_dir}/entity.pem

    # Run the seed node.
    run_seed_node

    # Run the key manager node.
    run_keymanager_node

    # Run the validator nodes.
    for idx in $(seq 1 $nodes); do
        local datadir=${base_datadir}-${idx}

        let tm_port=(idx-1)+26656
        let grpc_debug_port=tm_port+36656

        ${EKIDEN_NODE} \
            --log.level info \
            --log.file ${committee_dir}/validator-${idx}.log \
            --grpc.log.verbose_debug \
            --grpc.debug.port ${grpc_debug_port} \
            --epochtime.backend ${epochtime_backend} \
            --epochtime.tendermint.interval 30 \
            --beacon.backend tendermint \
            --metrics.mode none \
            --storage.backend client \
            --storage.client.address 127.0.0.1:${storage_port} \
            --scheduler.backend trivial \
            --registry.backend tendermint \
            --roothash.backend tendermint \
            --tendermint.core.genesis_file ${genesis_file} \
            --tendermint.core.listen_address tcp://0.0.0.0:${tm_port} \
            --tendermint.consensus.timeout_commit 250ms \
            --tendermint.debug.addr_book_lenient \
            --keymanager.client.address 127.0.0.1:9003 \
            --keymanager.client.certificate ${committee_dir}/key-manager/tls_identity_cert.pem \
            --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
            --datadir ${datadir} \
            &

        # HACK HACK HACK HACK HACK
        #
        # If you don't attempt to start the Tendermint Prometheus HTTP server
        # (even if it is doomed to fail due to ekiden already listening on the
        # port), and you launch all the validatiors near simultaniously, there
        # is a high chance that at least one of the validators will get upset
        # and start refusing connections.
        sleep 3
    done
}

# Run a compute node.
#
# Requires that EKIDEN_TM_GENESIS_FILE and EKIDEN_STORAGE_PORT are
# set. Exits with an error otherwise.
#
# Arguments:
#   id - compute node index
#   runtime - name of the runtime to use
#
# Any additional arguments are passed to the Go node.
run_compute_node() {
    local id=$1
    shift || true
    local runtime=$1
    shift || true
    local extra_args=$*

    # Ensure the genesis file and storage port are available.
    if [[ "${EKIDEN_TM_GENESIS_FILE:-}" == "" || "${EKIDEN_STORAGE_PORT:-}" == "" ]]; then
        echo "ERROR: Tendermint genesis and/or storage port file not configured. Did you use run_backend_tendermint_committee?"
        exit 1
    fi

    local data_dir=${EKIDEN_COMMITTEE_DIR}/worker-$id
    rm -rf ${data_dir}
    local log_file=${EKIDEN_COMMITTEE_DIR}/worker-$id.log
    rm -rf ${log_file}

    # Generate port number.
    let client_port=id+11000
    let p2p_port=id+12000
    let tm_port=id+13000

    local runtime_target=""
    local runtime_ext=""
    if [[ "${EKIDEN_TEE_HARDWARE}" == "intel-sgx" ]]; then
        runtime_target="x86_64-fortanix-unknown-sgx"
        runtime_ext=".sgxs"
    fi

    ${EKIDEN_NODE} \
        --log.level info \
        --grpc.log.verbose_debug \
        --storage.backend cachingclient \
        --storage.cachingclient.file ${data_dir}/storage-cache \
        --storage.client.address 127.0.0.1:${EKIDEN_STORAGE_PORT} \
        --epochtime.backend ${EKIDEN_EPOCHTIME_BACKEND} \
        --epochtime.tendermint.interval 30 \
        --beacon.backend tendermint \
        --metrics.mode none \
        --scheduler.backend trivial \
        --registry.backend tendermint \
        --roothash.backend tendermint \
        --tendermint.core.genesis_file ${EKIDEN_TM_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:${tm_port} \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        ${EKIDEN_TEE_HARDWARE:+--ias.proxy_addr 127.0.0.1:${EKIDEN_IAS_PROXY_PORT}} \
        --keymanager.client.address 127.0.0.1:9003 \
        --keymanager.client.certificate ${EKIDEN_COMMITTEE_DIR}/key-manager/tls_identity_cert.pem \
        --worker.backend sandboxed \
        --worker.binary ${EKIDEN_RUNTIME_LOADER} \
        --worker.runtime.binary ${WORKDIR}/target/${runtime_target}/debug/${runtime}${runtime_ext} \
        --worker.runtime.id 0000000000000000000000000000000000000000000000000000000000000000 \
        ${EKIDEN_TEE_HARDWARE:+--worker.runtime.sgx_ids 0000000000000000000000000000000000000000000000000000000000000000} \
        --worker.client.port ${client_port} \
        --worker.p2p.port ${p2p_port} \
        --worker.leader.max_batch_size 1 \
        --worker.entity_private_key ${EKIDEN_ENTITY_PRIVATE_KEY} \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --datadir ${data_dir} \
        ${extra_args} 2>&1 | tee ${log_file} | sed "s/^/[compute-node-${id}] /" &
}

# Cat all compute node logs.
cat_compute_logs() {
    cat ${EKIDEN_COMMITTEE_DIR}/worker-*.log
}

# Wait for a number of compute nodes to register.
#
# Arguments:
#   nodes - number of nodes to wait for
wait_compute_nodes() {
    local nodes=$1

    ${EKIDEN_NODE} debug dummy wait-nodes \
        --address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --nodes $nodes
}

# Set epoch.
#
# Arguments:
#   epoch - epoch to set
set_epoch() {
    local epoch=$1

    ${EKIDEN_NODE} debug dummy set-epoch \
        --address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --epoch $epoch
}

# Run a key manager node.
#
# Any arguments are passed to the key manager node.
run_keymanager_node() {
    local extra_args=$*

    local data_dir=${EKIDEN_COMMITTEE_DIR}/key-manager
    rm -rf ${data_dir}
    local log_file=${EKIDEN_COMMITTEE_DIR}/key-manager.log
    rm -rf ${log_file}

    local runtime_target=""
    local runtime_ext=""
    if [[ "${EKIDEN_TEE_HARDWARE}" == "intel-sgx" ]]; then
        runtime_target="x86_64-fortanix-unknown-sgx"
        runtime_ext=".sgxs"
    fi

    let tm_port=13900

    ${EKIDEN_NODE} \
        --log.level info \
        --grpc.log.verbose_debug \
        --storage.backend cachingclient \
        --storage.cachingclient.file ${data_dir}/storage-cache \
        --storage.client.address 127.0.0.1:${EKIDEN_STORAGE_PORT} \
        --epochtime.backend ${EKIDEN_EPOCHTIME_BACKEND} \
        --epochtime.tendermint.interval 30 \
        --beacon.backend tendermint \
        --metrics.mode none \
        --scheduler.backend trivial \
        --registry.backend tendermint \
        --roothash.backend tendermint \
        --tendermint.core.genesis_file ${EKIDEN_TM_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:${tm_port} \
        --tendermint.consensus.timeout_commit 250ms \
        --tendermint.debug.addr_book_lenient \
        ${EKIDEN_TEE_HARDWARE:+--ias.proxy_addr 127.0.0.1:${EKIDEN_IAS_PROXY_PORT}} \
        ${EKIDEN_TEE_HARDWARE:+--keymanager.tee_hardware ${EKIDEN_TEE_HARDWARE}} \
        --keymanager.loader ${EKIDEN_RUNTIME_LOADER} \
        --keymanager.runtime ${EKIDEN_ROOT_PATH}/target/${runtime_target}/debug/ekiden-keymanager-runtime${runtime_ext} \
        --keymanager.port 9003 \
        --tendermint.seeds "${EKIDEN_SEED_NODE_ID}@127.0.0.1:${EKIDEN_SEED_NODE_PORT}" \
        --datadir ${data_dir} \
        ${extra_args} 2>&1 | tee ${log_file} | sed "s/^/[key-manager] /" &
}

# Run a seed node.
#
# Requires that EKIDEN_TM_GENESIS_FILE and EKIDEN_STORAGE_PORT are
# set. Exits with an error otherwise.
#
# Sets:
#   EKIDEN_SEED_NODE_ID
#   EKIDEN_SEED_NODE_PORT
#
# Any arguments are passed to the Go node.
run_seed_node() {
    local extra_args=$*

    # Ensure the genesis file and storage port are available.
    if [[ "${EKIDEN_TM_GENESIS_FILE:-}" == "" || "${EKIDEN_STORAGE_PORT:-}" == "" ]]; then
        echo "ERROR: Tendermint genesis and/or storage port file not configured. Did you use run_backend_tendermint_committee?"
        exit 1
    fi

    local data_dir=${EKIDEN_COMMITTEE_DIR}/seed-$id
    rm -rf ${data_dir}
    local log_file=${EKIDEN_COMMITTEE_DIR}/seed-$id.log
    rm -rf ${log_file}

    # Generate port number.
    let EKIDEN_SEED_NODE_PORT=id+23000

    ${EKIDEN_NODE} \
        --log.level info \
        --metrics.mode none \
        --tendermint.core.genesis_file ${EKIDEN_TM_GENESIS_FILE} \
        --tendermint.core.listen_address tcp://0.0.0.0:${EKIDEN_SEED_NODE_PORT} \
        --tendermint.seed_mode \
        --tendermint.debug.addr_book_lenient \
        --datadir ${data_dir} \
        ${extra_args} 2>&1 | tee ${log_file} | sed "s/^/[seed-node-${id}] /" &

    # 'show-node-id' relies on key file to be present
    while [ ! -f "${data_dir}/tendermint/config/priv_validator_key.json" ]
    do
      echo "Waiting for seed node to start..."
      sleep 2
    done

    EKIDEN_SEED_NODE_ID=$(${EKIDEN_NODE} debug tendermint show-node-id \
        --dataDir ${data_dir})
    export EKIDEN_SEED_NODE_ID
    export EKIDEN_SEED_NODE_PORT
}

# Run a basic client.
#
# Sets EKIDEN_CLIENT_PID to the PID of the client process.
#
# Required arguments:
#   runtime        - name of the runtime enclave to use (without .so); the
#                    enclave must be available under target/enclave
#   client         - name of the client binary to use (without -client)
run_basic_client() {
    local runtime=$1
    local client=$2

    local log_file=${EKIDEN_COMMITTEE_DIR}/client.log
    rm -rf ${log_file}

    ${WORKDIR}/target/debug/${client}-client \
        --node-address unix:${EKIDEN_VALIDATOR_SOCKET} \
        --runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        2>&1 | tee ${log_file} | sed "s/^/[client] /" &
    EKIDEN_CLIENT_PID=$!
}

# Global test counter used for parallelizing jobs.
E2E_TEST_COUNTER=0

# Run a specific test scenario.
#
# Required named arguments:
#
#   name           - unique test name
#   scenario       - function that will start the compute nodes; see the
#                    scenario function section below for details
#   backend_runner - function that will prepare and run the backend services
#   runtime        - name of the runtime enclave to use (without .so); the
#                    enclave must be available under target/enclave
#
# Optional named arguments:
#
#   post_km_hook    - function that will run after the key manager node
#                     has been started
#   on_success_hook - function that will run after the client successfully
#                     exits (default: assert_basic_success)
#   client_runner   - function that will run the client (default: run_basic_client)
#   client          - name of the client binary to use, without -client (default: none)
#
# Scenario function:
#
# The scenario function defines what will be executed during the test. It will
# receive the following arguments when called:
#
#   runtime - the name of the runtime to use
#
run_test() {
    # Required arguments.
    local name scenario backend_runner runtime
    # Optional arguments with default values.
    local pre_init_hook=""
    local post_km_hook=""
    local on_success_hook="assert_basic_success"
    local start_client_first=0
    local client_runner=run_basic_client
    local client="none"
    # Load named arguments that override defaults.
    local "${@}"

    # Check if we should run this test.
    if [[ "${TEST_FILTER:-}" == "" ]]; then
        local test_index=$E2E_TEST_COUNTER
        let E2E_TEST_COUNTER+=1 1

        if [[ -n ${BUILDKITE_PARALLEL_JOB+x} ]]; then
            let test_index%=BUILDKITE_PARALLEL_JOB_COUNT 1

            if [[ $BUILDKITE_PARALLEL_JOB != $test_index ]]; then
                echo "Skipping test '${name}' (assigned to different parallel build)."
                return
            fi
        fi
    elif [[ "${TEST_FILTER}" != "${name}" ]]; then
        return
    fi

    echo -e "\n\e[36;7;1mRUNNING TEST:\e[27m ${name}\e[0m\n"

    if [[ "${pre_init_hook}" != "" ]]; then
        $pre_init_hook
    fi

    if [[ "${start_client_first}" == 0 ]]; then
        # Start backend.
        $backend_runner
        sleep 1
    fi

    # Run the client.
    $client_runner $runtime $client
    local client_pid=${EKIDEN_CLIENT_PID:-""}

    if [[ "${start_client_first}" == 1 ]]; then
        # Start backend.
        $backend_runner
        sleep 1
    fi

    # Run post key-manager startup hook.
    if [[ "$post_km_hook" != "" ]]; then
        $post_km_hook
    fi

    # Run scenario.
    $scenario $runtime

    # Wait on the client and check its exit status.
    if [ "${client_pid}" != "" ]; then
        wait ${client_pid}
    fi

    # Run on success hook.
    if [[ "$on_success_hook" != "" ]]; then
        $on_success_hook
    fi

    # Cleanup.
    cleanup
}

####################
# Common assertions.
####################

# Assert that there are were no round timeouts.
assert_no_round_timeouts() {
    cat_compute_logs | (! grep -q 'FireTimer')
    cat_compute_logs | (! grep -q 'round failed')
}

# Assert that there were no discrepancies.
assert_no_discrepancies() {
    cat_compute_logs | (! grep -q 'discrepancy detected')
}

# Assert that all computations ran successfully without hiccups.
assert_basic_success() {
    assert_no_round_timeouts
    assert_no_discrepancies
}
