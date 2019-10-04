#!/bin/bash

set -euo pipefail

covfile=$(mktemp coverage-e2e-XXXXXXXXXX.txt)

exec ./go/oasis-node/integrationrunner/integrationrunner.test \
  -test.coverprofile "$covfile" \
  -integration.run \
  -- "$@"
