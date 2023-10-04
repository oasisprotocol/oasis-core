#!/bin/bash

# Check if the name of the script is provided.
if [ $# -lt 1 ]; then
    echo "Usage: $0 <script-name> [args...]"
    exit 1
fi

# Pop the name to the script.
script_name="$1"
shift

# Construct the path to the script.
script_path="$PWD/.buildkite/scripts/$script_name"

# Check if the specified script exists.
if [ ! -f "$script_path" ]; then
    echo "Error: Script '$script_path' not found."
    exit 1
fi

# Don't enable the 'e' option, which would cause the script to immediately
# exit if the script failed.
set -uo pipefail

# Execute the script with the remaining arguments.
bash "$script_path" "$@"

# Capture the exit status.
exit_status=$?

# Upload artifacts always.
buildkite-agent artifact upload "coverage-merged-e2e-*.txt;/tmp/e2e/**/*.log;/tmp/e2e/**/genesis.json;/tmp/e2e/**/runtime_genesis.json"

# Exit with the status of the script.
exit $exit_status
