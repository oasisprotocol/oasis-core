#!/bin/bash

################################################################
# This script tests an Ekiden cmd tools.
#
# Usage:
# test_ekiden_tools.sh
################################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# For automatic cleanup on exit.
source .buildkite/scripts/common.sh

config="single_node"
ekiden_node="$(pwd)/go/ekiden/ekiden"

# Prepare single node configuration.
data_dir="/tmp/ekiden-single-node"
rm -rf "${data_dir}"
cp -R "configs/${config}" "${data_dir}"
chmod -R go-rwx "${data_dir}"

test_keymanager_tools() {
    # Policy options
    policy_file="${data_dir}/km_policy.cbor"
    signature_file="${data_dir}/km_policy.cbor.sign"
    key_file="${data_dir}/p2p.pem"
    status_file="${data_dir}/km_status.json"

    # Generate a simple policy without rules.
    ${ekiden_node} keymanager init_policy \
      --keymanager.policy.id 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
      --keymanager.policy.serial 1 \
      --keymanager.policy.file "${policy_file}"

    test -s "${policy_file}"

    # Generate policy for two KM enclaves and specific query and replicate
    # permissions.
    ${ekiden_node} keymanager init_policy \
      --keymanager.policy.id 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
      --keymanager.policy.serial 1 \
      --keymanager.policy.enclave.id 10000000000000000000000000000000000000000000000000000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdee \
        --keymanager.policy.may.replicate 1000000000000000000000000000000000000000000000000000000000000000fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321,1000000000000000000000000000000000000000000000000000000000000000fedcba0987654321fedcba0987654321fedcba0987654321ffdcba0987654320 \
        --keymanager.policy.may.query fedcba0987654321fedcba0987654321fedcba0987654321ffdcba0987654320=1000000000000000000000000000000000000000000000000000000000000000fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321,10000000000000000000000000000000000000000000000000000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
      --keymanager.policy.enclave.id 20000000000000000000000000000000000000000000000000000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdee \
        --keymanager.policy.may.query fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654320=2000000000000000000000000000000000000000000000000000000000000000fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 \
      --keymanager.policy.file "${policy_file}"

    test -s "${policy_file}"

    # Print the policy to stdout in JSON
    ${ekiden_node} keymanager verify_policy \
      --keymanager.policy.file "${policy_file}" \
      --keymanager.policy.ignore.signature \
      -v | grep "\"enclaves\":"

    # Sign and verify this policy with hardcoded test keys.
    for tk in 1 2 3; do
        ${ekiden_node} keymanager sign_policy \
          --keymanager.policy.file "${policy_file}" \
          --keymanager.policy.signature.file "${signature_file}.${tk}" \
          --keymanager.policy.testkey ${tk}

        test -s "${signature_file}.${tk}"

        ${ekiden_node} keymanager verify_policy \
          --keymanager.policy.file "${policy_file}" \
          --keymanager.policy.signature.file "${signature_file}.${tk}" \
          --debug.allow_test_keys
    done

    # Generate status file and include the policy with test key signatures.
    ${ekiden_node} keymanager init_status \
        --keymanager.status.id 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
        --keymanager.status.file "${status_file}" \
        --keymanager.policy.file "${policy_file}" \
        --keymanager.policy.signature.file "${signature_file}.1" \
        --keymanager.policy.signature.file "${signature_file}.2" \
        --keymanager.policy.signature.file "${signature_file}.3" \
        --debug.allow_test_keys

    test -s "${status_file}"

    # Sign and verify this policy with given private key.
    ${ekiden_node} keymanager sign_policy \
      --keymanager.policy.file "${policy_file}" \
      --keymanager.policy.signature.file "${signature_file}" \
      --keymanager.policy.key.file "${key_file}"

    test -s "${signature_file}"

    ${ekiden_node} keymanager verify_policy \
      --keymanager.policy.file "${policy_file}" \
      --keymanager.policy.signature.file "${signature_file}"

    # Generate status file and include the policy with given signature.
    ${ekiden_node} keymanager init_status \
        --keymanager.status.id 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
        --keymanager.status.file "${status_file}" \
        --keymanager.policy.file "${policy_file}" \
        --keymanager.policy.signature.file "${signature_file}" \
        --keymanager.status.initialized \
        --keymanager.status.secure \
        --keymanager.status.checksum fedbca0987654321fedbca0987654321fedbca0987654321fedbca0987654321

    test -s "${status_file}"
}

test_keymanager_tools
