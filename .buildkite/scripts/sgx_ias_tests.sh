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
export OASIS_TEE_HARDWARE=intel-sgx
# Allow use of usnafe km policy keys.
export OASIS_UNSAFE_KM_POLICY_KEYS=1
# Allow debug encalves (tests are running against developemnt endpoint).
export OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES=1

make all
.buildkite/scripts/test_e2e.sh --scenario e2e/runtime/runtime-encryption
