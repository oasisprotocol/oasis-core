#!/bin/bash -e

output=$(</dev/stdin)
HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cp $HERE/Dockerfile.runtime $HERE/Dockerfile.generated
echo "ENV" $output >> $HERE/Dockerfile.generated
