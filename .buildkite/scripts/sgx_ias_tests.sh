#! /bin/bash

set -euxo pipefail

# Script invoked from .buildkite/iastests.pipeline.yml

set +x
OASIS_IAS_APIKEY=$(cat ~/.oasis-ias/api_key)
export OASIS_IAS_APIKEY
OASIS_IAS_SPID=$(cat ~/.oasis-ias/spid)
export OASIS_IAS_SPID
set -x

export GO_BUILD_E2E_COVERAGE=1
# Ensure AVR verify is not skipped.
unset OASIS_UNSAFE_SKIP_AVR_VERIFY
# Allow debug enclaves (tests are running against developemnt endpoint).
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES=1
# Use Intel SGX.
export OASIS_TEE_HARDWARE=intel-sgx

make all
.buildkite/scripts/test_e2e.sh --scenario e2e/runtime/runtime-encryption
