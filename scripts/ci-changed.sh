#!/bin/bash
# exit CI if not on master and no files in a regex are changed.
if [ `git symbolic-ref --short HEAD` == "master" ]; then
  exit 0
fi

# when writing arguments, separate them with regex for grep
IFS="|"
MATCH="$*"
if [[ $(git diff --name-only origin/master | grep -P "^($MATCH)") ]]; then
  echo "Repo diverged from master. Running CI Job"
  exit 0
else
  circleci step halt
fi
