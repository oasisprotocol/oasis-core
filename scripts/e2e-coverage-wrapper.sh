#!/bin/bash

set -euo pipefail

# Determine coverage file location.
covfile=$(mktemp coverage-e2e-XXXXXXXXXX.txt)

# Run the specified binary with E2E coverage instrumentation.
exec ${E2E_COVERAGE_BINARY} \
  -test.coverprofile "$covfile" \
  -test.run "^TestCoverageE2E$" \
  -- "$@"
