#! /bin/bash

# This script compares all metrics of the last benchmark batch from the feature
# branch to the last batch of the master branch. If any thresholds are
# exceeded, the issue is reported to the slack channel and error code is
# returned.
#
# Script should be invoked from .buildkite/benchmarks.pipeline.yml. Required
# env variables:
# BUILDKITE_BUILD_URL - URL for seeing detailed testing and comparison log (e.g. https://buildkite.com/oasisprotocol/oasis-core-daily-benchmarks/builds/xx)
# METRICS_QUERY_ADDR - address of Prometheus server (e.g. http://localhost:9090)
# METRICS_SOURCE_GIT_BRANCH - name of feature branch on git (e.g. jsmith/feature/abc)
# METRICS_TARGET_GIT_BRANCH - name of master branch on git (e.g. master)
# METRICS_THRESHOLDS - max or min thresholds flags (e.g. --max_threshold.cpu.avg_ratio 1.05)
# SCENARIOS - names of scenario(s) to compare (e.g. e2e/runtime/runtime)
# SLACK_WEBHOOK_URL - slack webhook for reporting (e.g. https://hooks.slack.com/services/xxxxxx)

set -ux

./go/oasis-test-runner/oasis-test-runner cmp \
  --metrics.address $METRICS_QUERY_ADDR \
  --metrics.source.git_branch $METRICS_SOURCE_GIT_BRANCH \
  --metrics.target.git_branch $METRICS_TARGET_GIT_BRANCH \
  --scenario $SCENARIOS \
  --log.level INFO \
  --log.format JSON \
  $METRICS_THRESHOLDS \
  >out.txt 2>&1
CMP_RETURN_CODE=$?

# Show stdout and stderr in logs for debugging.
cat out.txt

# Escape double quotes for JSON.
CMP_ERROR_LINES=`cat out.txt | sed "s/\"/\\\\\\\\\"/g" | grep error`

if [ $CMP_RETURN_CODE != 0 ]; then
  # Post error to slack channel.
  curl -H "Content-Type: application/json" \
       -X POST \
       --data "{\"text\": \"$BUILDKITE_PIPELINE_NAME for branch \`$METRICS_SOURCE_GIT_BRANCH\` failed. Visit $BUILDKITE_BUILD_URL for details.\", \"attachments\":[{\"title\":\"Relevant error lines\",\"text\":\"$CMP_ERROR_LINES\"}]}" \
       "$SLACK_WEBHOOK_URL"

  # Exit with non-zero exit code, so that the buildkite build will be
  # marked as failed.
  exit 1
fi
