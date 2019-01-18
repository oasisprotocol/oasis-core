################################
# Common functions for E2E tests
################################

# Temporary test base directory.
TEST_BASE_DIR=$(mktemp -d --tmpdir ekiden-e2e-XXXXXXXXXX)

# Run a Tendermint validator committee and a storage node.
#
# Sets:
#   EKIDEN_COMMITTEE_DIR
#   EKIDEN_TM_GENESIS_FILE
#   EKIDEN_STORAGE_PORT
#   EKIDEN_EPOCHTIME_BACKEND
#   EKIDEN_EXTRA_ARGS
#
# Arguments:
#   epochtime_backend - epochtime backend (default: tendermint)
#   id - commitee identifier (default: 1)
#
# Any additional arguments are passed to the validator Go node and
# all compute nodes.
run_backend_tendermint_committee() {
    local epochtime_backend=${1:-tendermint}
    shift || true
    local id=${1:-1}
    shift || true
    local extra_args=$*

    local committee_dir=${TEST_BASE_DIR}/committee-${id}
    local base_datadir=${committee_dir}/committee-data
    local validator_files=""
    let nodes=3

    # Provision the validators.
    for idx in $(seq 1 $nodes); do
        local datadir=${base_datadir}-${idx}
        rm -rf ${datadir}

        let port=(idx-1)+26656
        ${WORKDIR}/go/ekiden/ekiden \
            tendermint provision_validator \
            --datadir ${datadir} \
            --node_addr 127.0.0.1:${port} \
            --node_name ekiden-committee-node-${idx} \
            --validator_file ${datadir}/validator.json
        validator_files="$validator_files $datadir/validator.json"
    done

    # Create the genesis document.
    local genesis_file=${committee_dir}/genesis.json
    rm -Rf ${genesis_file}

    ${WORKDIR}/go/ekiden/ekiden \
        tendermint init_genesis \
        --genesis_file ${genesis_file} \
        ${validator_files}

    # Run the storage node.
    local storage_datadir=${committee_dir}/storage
    local storage_port=60000
    rm -Rf ${storage_datadir}

    ${WORKDIR}/go/ekiden/ekiden \
        storage node \
        --datadir ${storage_datadir} \
        --grpc.port ${storage_port} \
        --log.file ${committee_dir}/storage.log \
        &

    # Run the validator nodes.
    for idx in $(seq 1 $nodes); do
        local datadir=${base_datadir}-${idx}

        let grpc_port=(idx-1)+42261
        let tm_port=(idx-1)+26656

        ${WORKDIR}/go/ekiden/ekiden \
            --log.level debug \
            --log.file ${committee_dir}/validator-${idx}.log \
            --grpc.port ${grpc_port} \
            --grpc.log.verbose_debug \
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
            --tendermint.log.debug \
            --datadir ${datadir} \
            ${extra_args} \
            &
    done

    # Export some variables so compute workers can find them.
    EKIDEN_COMMITTEE_DIR=${committee_dir}
    EKIDEN_STORAGE_PORT=${storage_port}
    EKIDEN_TM_GENESIS_FILE=${genesis_file}
    EKIDEN_EPOCHTIME_BACKEND=${epochtime_backend}
    EKIDEN_EXTRA_ARGS="${extra_args}"
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
    local cache_dir=${EKIDEN_COMMITTEE_DIR}/worker-cache-$id
    rm -rf ${cache_dir}
    local log_file=${EKIDEN_COMMITTEE_DIR}/worker-$id.log
    rm -rf ${log_file}

    # Generate port number.
    let grpc_port=id+10000
    let client_port=id+11000
    let p2p_port=id+12000
    let tm_port=id+13000

    ${WORKDIR}/go/ekiden/ekiden \
        --log.level debug \
        --grpc.port ${grpc_port} \
        --grpc.log.verbose_debug \
        --storage.backend client \
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
        --tendermint.log.debug \
        --worker.backend sandboxed \
        --worker.binary ${WORKDIR}/target/debug/ekiden-worker \
        --worker.cache_dir ${cache_dir} \
        --worker.runtime.binary ${WORKDIR}/target/enclave/${runtime}.so \
        --worker.runtime.id 0000000000000000000000000000000000000000000000000000000000000000 \
        --worker.client.port ${client_port} \
        --worker.p2p.port ${p2p_port} \
        --worker.leader.max_batch_size 1 \
        --worker.key_manager.address 127.0.0.1:9003 \
        --worker.key_manager.certificate ${WORKDIR}/tests/keymanager/km.pem \
        --datadir ${data_dir} \
        ${EKIDEN_EXTRA_ARGS} ${extra_args} 2>&1 | tee ${log_file} | sed "s/^/[compute-node-${id}] /" &
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

    ${WORKDIR}/go/ekiden/ekiden debug dummy wait-nodes --nodes $1
}

# Set epoch.
#
# Arguments:
#   epoch - epoch to set
set_epoch() {
    local epoch=$1

    ${WORKDIR}/go/ekiden/ekiden debug dummy set-epoch --epoch $epoch
}

# Run a key manager node.
#
# Any arguments are passed to the key manager node.
run_keymanager_node() {
    local extra_args=$*

    local db_dir=${TEST_BASE_DIR}/test-keymanager
    rm -rf ${db_dir}

    ${WORKDIR}/target/debug/ekiden-keymanager-node \
        --enclave ${WORKDIR}/target/enclave/ekiden-keymanager-trusted.so \
        --tls-certificate ${WORKDIR}/tests/keymanager/km.pem \
        --tls-key ${WORKDIR}/tests/keymanager/km-key.pem \
        --storage-backend dummy \
        --storage-path ${db_dir} \
        ${extra_args} &
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

    ${WORKDIR}/target/debug/${client}-client \
        --storage-backend remote \
        --mr-enclave $(cat ${WORKDIR}/target/enclave/${runtime}.mrenclave) \
        --test-runtime-id 0000000000000000000000000000000000000000000000000000000000000000 \
        &
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
#   client         - name of the client binary to use (without -client)
#
# Optional named arguments:
#
#   post_km_hook    - function that will run after the key manager node
#                     has been started
#   on_success_hook - function that will run after the client successfully
#                     exits (default: assert_basic_success)
#   client_runner   - function that will run the client (default: run_basic_client)
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
    local name scenario backend_runner runtime client
    # Optional arguments with default values.
    local post_km_hook=""
    local on_success_hook="assert_basic_success"
    local start_client_first=0
    local client_runner=run_basic_client
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

    # Start the key manager before starting anything else.
    run_keymanager_node
    sleep 1

    # Run post key-manager startup hook.
    if [[ "$post_km_hook" != "" ]]; then
        $post_km_hook
    fi

    if [[ "${start_client_first}" == 0 ]]; then
        # Start backend.
        $backend_runner
        sleep 1
    fi

    # Run the client.
    $client_runner $runtime $client
    local client_pid=$EKIDEN_CLIENT_PID

    if [[ "${start_client_first}" == 1 ]]; then
        # Start backend.
        $backend_runner
        sleep 1
    fi

    # Run scenario.
    $scenario $runtime

    # Wait on the client and check its exit status.
    wait ${client_pid}

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
