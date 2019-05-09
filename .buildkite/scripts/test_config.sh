#!/bin/bash

############################################################
# This script tests an Ekiden node configuration.
#
# Usage:
# test_config.sh <config>
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# For automatic cleanup on exit.
source .buildkite/scripts/common.sh

config="$1"
ekiden_node="${EKIDEN_ROOT_PATH:-"."}/go/ekiden/ekiden"
client="${EKIDEN_ROOT_PATH:-"."}/target/debug/simple-keyvalue-client"

# Prepare single node configuration.
data_dir="/tmp/ekiden-single-node"
rm -rf "${data_dir}"
cp -R "configs/${config}" "${data_dir}"
chmod -R go-rwx "${data_dir}"

# Start the Ekiden node.
${ekiden_node} --config configs/${config}.yml &

# Wait for the node to be registered.
${ekiden_node} debug dummy wait-nodes \
    --address unix:${data_dir}/internal.sock \
    --nodes 1

# Run the simple key/value client against the node.
${client} \
    --node-address unix:${data_dir}/internal.sock \
    --runtime-id ${EKIDEN_RUNTIME_ID:-"0000000000000000000000000000000000000000000000000000000000000000"}
