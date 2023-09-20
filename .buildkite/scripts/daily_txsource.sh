#! /bin/bash

set -euxo pipefail

# Script invoked from .buildkite/longtests.pipeline.yml

if [[ $BUILDKITE_RETRY_COUNT == 0 ]]; then
    ./.buildkite/scripts/test_e2e.sh \
        --metrics.address $METRICS_PUSH_ADDR \
        --metrics.labels instance=$BUILDKITE_PIPELINE_NAME-$BUILDKITE_BUILD_NUMBER \
        --scenario_timeout 900m \
        --scenario e2e/runtime/txsource-multi \
        "$@"

    # In case of success daily artifacts are not interesting and can be removed.
    rm -rf /var/tmp/longtests/*
else
    curl -H "Content-Type: application/json" \
        -X POST \
        --data "{\"text\": \"Daily transaction source tests failure\"}" \
        "$SLACK_WEBHOOK_URL"

    # Exit with non-zero exit code, so that the buildkite build will be
    # marked as failed.
    exit 1
fi
