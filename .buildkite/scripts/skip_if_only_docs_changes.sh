# Source this file rather than fork-exec-ing it.

only_docs_changes() {
  # https://git-scm.com/docs/gitglossary#Documentation/gitglossary.txt-aiddefpathspecapathspec
  test -n "$BUILDKITE_PULL_REQUEST_BASE_BRANCH" &&
    git diff --quiet "refs/remotes/origin/$BUILDKITE_PULL_REQUEST_BASE_BRANCH.." -- \
      ':(exclude).changelog' \
      ':(exclude)CHANGELOG.md' \
      ':(exclude)CONTRIBUTING.md' \
      ':(exclude)LICENSE' \
      ':(exclude)README.md' \
      ':(exclude)SECURITY.md'
}

if only_docs_changes; then
  echo "Only docs changes. Skipping"
  exit 0
fi
