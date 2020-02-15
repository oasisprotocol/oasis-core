# Source this file rather than fork-exec-ing it.

. .buildkite/scripts/common.sh

if only_docs_changes; then
  echo "Only docs changes. Skipping"
  exit 0
fi
