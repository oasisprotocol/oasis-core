#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import subprocess
import sys

def benchmark_crate(benchmarks, crate):
    have_errors = False

    # Run benchmark using JSON output.
    print("=== Benchmarking crate '{}' ===".format(crate))
    try:
        output = subprocess.check_output(
            ['cargo', 'bench', '-p', crate, '--', '-Z', 'unstable-options', '--format', 'json']
        )
    except subprocess.CalledProcessError as error:
        output = error.output
        have_errors = True

    # Process resulting lines to create a build artifact.
    for line in output.split('\n'):
        if not line:
            continue

        event = json.loads(line)

        if event['type'] == 'bench':
            benchmarks[event['name']] = {'median': event['median'], 'deviation': event['deviation']}
            print("{name}: {median} ns / iter, deviation {deviation} ns".format(**event))
        elif event['type'] == 'test' and event['event'] == 'failed':
            print("ERROR: Test '{name}' has failed with following output:".format(**event))
            print("===")
            print(event['stdout'])
            print("===")
            have_errors = True

    return have_errors

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=None)
    parser.add_argument('crate', type=str, nargs='+',
                        help="Crates to benchmark")
    parser.add_argument('--output', type=str,
                        help="Output filename")
    parser.add_argument('--compare-to', type=str,
                        help="Previous output to compare to")
    parser.add_argument('--fail-deviations', type=int, default=3,
                        help="Fail if new benchmark is more than this many deviations slower")
    args = parser.parse_args()

    # Run benchmarks.
    benchmarks = {}
    have_errors = False
    for crate in args.crate:
        if benchmark_crate(benchmarks.setdefault(crate, {}), crate):
            have_errors = True

    if have_errors:
        print("ERROR: Benchmarks completed with errors, aborting.")
        sys.exit(1)

    # Compare against previous results and abort if these are worse.
    if args.compare_to:
        print("=== Comparing against previous results ===")
        try:
            with open(args.compare_to) as compare:
                compare = json.load(compare)
        except IOError:
            print("WARNING: Failed to load previous results from '{}'.".format(args.compare_to))
            compare = {}

        for crate, latest in benchmarks.items():
            previous = compare.get(crate, None)
            if previous is None:
                continue

            for benchmark, result in latest.items():
                previous_result = previous.get(benchmark, None)
                if previous_result is None:
                    continue

                diff = result['median'] - previous_result['median']
                print("{crate}/{name}: difference {diff} ns / iter, previous deviation {deviation} ns".format(
                    crate=crate,
                    name=benchmark,
                    diff=diff,
                    deviation=previous_result['deviation'],
                ))

                max_diff = max(args.fail_deviations * previous_result['deviation'], 100)

                if diff > max_diff:
                    print("ERROR: Benchmark '{}' is much slower in the current build:".format(benchmark))
                    print("  Runtime:", result['median'], "ns")
                    print("  Difference:", diff, "ns")
                    print("  Deviation:", previous_result['deviation'], "ns")
                    print("")
                    # TODO: Performance on CI is too variable to fail builds due to slow benchmarks.
                    # have_errors = True

    # Store results.
    if args.output:
        with open(args.output, 'w') as output:
            json.dump(benchmarks, output)

    if have_errors:
        sys.exit(1)
