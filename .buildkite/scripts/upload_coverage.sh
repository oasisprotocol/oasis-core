#!/bin/bash

set -euxo pipefail

set +x
CODECOV_TOKEN=$(cat ~/.codecov/oasis_core_api_token)
export CODECOV_TOKEN
set -x
bash <(curl -s https://codecov.io/bash) -Z -f merged-coverage.txt
