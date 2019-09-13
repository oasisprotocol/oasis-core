#!/bin/bash -e

DATADIR=$(mktemp -d --tmpdir ekiden-regenerate-XXXXXXXXXX)

EKIDEN_BINARY=${EKIDEN_BINARY:-"./go/ekiden/ekiden"}
EKIDEN_KM_BINARY=${EKIDEN_KM_BINARY:-"./target/x86_64-fortanix-unknown-sgx/debug/ekiden-keymanager-runtime.sgxs"}
EKIDEN_RUNTIME_BINARY=${EKIDEN_RUNTIME_BINARY:-"./target/x86_64-fortanix-unknown-sgx/debug/simple-keyvalue.sgxs"}
EKIDEN_RUNTIME_ID=${EKIDEN_RUNTIME_ID:-"0000000000000000000000000000000000000000000000000000000000000000"}
EKIDEN_KM_RUNTIME_ID=${EKIDEN_KM_RUNTIME_ID:-"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
EKIDEN_RUNTIME_VERSION=${EKIDEN_RUNTIME_VERSION:-"0x0000000000030000"}
EKIDEN_KM_RUNTIME_VERSION=${EKIDEN_KM_RUNTIME_VERSION:-"0x0000000000030000"}
# SGX MRSIGNER used to sign enclaves (default is the Fortanix test key).
EKIDEN_MRSIGNER=${EKIDEN_MRSIGNER:-"9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a"}

SINGLE_NODE_DIR=${SINGLE_NODE_DIR:-"./configs/single_node/"}
SINGLE_NODE_SGX_DIR=${SINGLE_NODE_SGX_DIR:-"./configs/single_node_sgx/"}

generate_km_status_file() {
    EKIDEN_KM_MRENCLAVE=($(sha256sum ${EKIDEN_KM_BINARY}))
    EKIDEN_RUNTIME_MRENCLAVE=($(sha256sum ${EKIDEN_RUNTIME_BINARY}))

    # Generate KM policy, sign it, and generate status file.
    ${EKIDEN_BINARY} \
        keymanager init_policy \
        --debug.allow_test_keys \
        --keymanager.policy.file "${DATADIR}/km_policy.cbor" \
        --keymanager.policy.id ${EKIDEN_KM_RUNTIME_ID} \
        --keymanager.policy.serial 1 \
        --keymanager.policy.enclave.id "${EKIDEN_MRSIGNER}${EKIDEN_KM_MRENCLAVE}" \
        --keymanager.policy.may.query "${EKIDEN_RUNTIME_ID}=${EKIDEN_MRSIGNER}${EKIDEN_RUNTIME_MRENCLAVE}"

    for i in 1 2 3; do
        ${EKIDEN_BINARY} \
            keymanager sign_policy \
            --debug.allow_test_keys \
            --keymanager.policy.file "${DATADIR}/km_policy.cbor" \
            --keymanager.policy.signature.file "${DATADIR}/km_policy.cbor.sign.$i" \
            --keymanager.policy.testkey $i
    done

    ${EKIDEN_BINARY} \
        keymanager init_status \
        --debug.allow_test_keys \
        --keymanager.status.id ${EKIDEN_KM_RUNTIME_ID} \
        --keymanager.status.file "${DATADIR}/km_status.json" \
        --keymanager.policy.file "${DATADIR}/km_policy.cbor" \
        --keymanager.policy.signature.file "${DATADIR}/km_policy.cbor.sign.1" \
        --keymanager.policy.signature.file "${DATADIR}/km_policy.cbor.sign.2" \
        --keymanager.policy.signature.file "${DATADIR}/km_policy.cbor.sign.3"
}

#
# Use the same validator.
#

${EKIDEN_BINARY}\
    registry node init \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --node.consensus_address 127.0.0.1:26656 \
    --node.role validator

rm ${DATADIR}/tls_identity*
cp ${DATADIR}/*.pem ${SINGLE_NODE_DIR}/
cp ${DATADIR}/node_genesis.json ${SINGLE_NODE_DIR}/
cp ${DATADIR}/*.pem ${SINGLE_NODE_SGX_DIR}/
cp ${DATADIR}/node_genesis.json ${SINGLE_NODE_SGX_DIR}/

#
# Non-SGX config.
#

${EKIDEN_BINARY}\
    registry runtime init_genesis \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --runtime.id ${EKIDEN_RUNTIME_ID} \
    --runtime.replica_group_size 1 \
    --runtime.replica_group_backup_size 0 \
    --runtime.storage_group_size 1 \
    --runtime.keymanager ${EKIDEN_KM_RUNTIME_ID} \
    --runtime.kind compute \
    --runtime.genesis.file runtime_genesis_nosgx.json \
    --runtime.version ${EKIDEN_RUNTIME_VERSION}

${EKIDEN_BINARY} \
    registry runtime init_genesis \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --runtime.id ${EKIDEN_KM_RUNTIME_ID} \
    --runtime.kind keymanager \
    --runtime.genesis.file keymanager_genesis_nosgx.json \
    --runtime.version ${EKIDEN_KM_RUNTIME_VERSION}

${EKIDEN_BINARY} \
    genesis init \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --genesis.file ${DATADIR}/genesis_nosgx.json \
    --runtime ${DATADIR}/keymanager_genesis_nosgx.json \
    --runtime ${DATADIR}/runtime_genesis_nosgx.json \
    --node ${SINGLE_NODE_DIR}/node_genesis.json

cp ${DATADIR}/genesis_nosgx.json ${SINGLE_NODE_DIR}/genesis.json

#
# SGX config.
#

${EKIDEN_BINARY}\
    registry runtime init_genesis \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --runtime.id ${EKIDEN_RUNTIME_ID} \
    --runtime.replica_group_size 1 \
    --runtime.replica_group_backup_size 0 \
    --runtime.storage_group_size 1 \
    --runtime.keymanager ${EKIDEN_KM_RUNTIME_ID} \
    --runtime.kind compute \
    --runtime.tee_hardware intel-sgx \
    --runtime.genesis.file runtime_genesis_sgx.json \
    --runtime.version ${EKIDEN_RUNTIME_VERSION}

${EKIDEN_BINARY} \
    registry runtime init_genesis \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --runtime.id ${EKIDEN_KM_RUNTIME_ID} \
    --runtime.kind keymanager \
    --runtime.tee_hardware intel-sgx \
    --runtime.genesis.file keymanager_genesis_sgx.json \
    --runtime.version ${EKIDEN_KM_RUNTIME_VERSION}

generate_km_status_file

${EKIDEN_BINARY} \
    genesis init \
    --datadir ${DATADIR} \
    --debug.allow_test_keys \
    --debug.test_entity \
    --genesis.file ${DATADIR}/genesis_sgx.json \
    --keymanager ${DATADIR}/km_status.json \
    --runtime ${DATADIR}/keymanager_genesis_sgx.json \
    --runtime ${DATADIR}/runtime_genesis_sgx.json \
    --node ${SINGLE_NODE_SGX_DIR}/node_genesis.json

cp ${DATADIR}/genesis_sgx.json ${SINGLE_NODE_SGX_DIR}/genesis.json
