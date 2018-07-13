#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys

import prometheus_client


def benchmark_crate(crate, registry):
    """Run benchmarks for a specific crate and parse results."""
    have_errors = False

    # Run benchmark using JSON output.
    print("Benchmarking crate '{}'...".format(crate))
    try:
        output = subprocess.check_output(
            ['cargo', 'bench', '-p', crate, '--', '-Z', 'unstable-options', '--format', 'json']
        )
    except subprocess.CalledProcessError as error:
        output = error.output
        have_errors = True

    # Process resulting output.
    for line in output.decode('utf8').split('\n'):
        if not line:
            continue

        event = json.loads(line)

        if event['type'] == 'bench':
            crate_id = re.sub(r'[^\w]+', '_', crate.lower())
            metric_id = re.sub(r'[^\w]+', '_', event['name'].lower())

            metric = prometheus_client.Gauge(
                'benchmarks_crate_{}_{}_median_nsec'.format(crate_id, metric_id),
                "Crate benchmark results for {} (benchmark {})".format(crate, event['name']),
                registry=registry,
            )
            metric.set(event['median'])

            print("{name}: {median} ns / iter, deviation {deviation} ns".format(**event))
        elif event['type'] == 'test' and event['event'] == 'failed':
            print("ERROR: Test '{name}' has failed with following output:".format(**event))
            print("===")
            print(event['stdout'])
            print("===")
            have_errors = True

    return have_errors


def benchmark_e2e(registry):
    """Run end-to-end benchmarks and parse results."""
    process = subprocess.Popen(
        ['./scripts/benchmark-e2e.sh', 'json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    while process.poll() is None:
        line = process.stdout.readline()
        if not line:
            break

        try:
            result = json.loads(line)
        except ValueError:
            continue

        benchmark_id = re.sub(r'[^\w]+', '_', result['title'].lower())

        # Latency.
        for percentile in (50, 90, 99, 999):
            latency_percentile = prometheus_client.Gauge(
                'benchmarks_e2e_{}_latency_p{}_msec'.format(benchmark_id, percentile),
                "E2E benchmark request latency for scenario '{}' ({}th percentile)".format(
                    result['title'], percentile
                ),
                registry=registry,
            )
            latency_percentile.set(result['latency']['p{}'.format(percentile)])

        for agg in ('min', 'avg', 'max', 'std_dev'):
            latency = prometheus_client.Gauge(
                'benchmarks_e2e_{}_latency_{}_msec'.format(benchmark_id, agg),
                "E2E benchmark request latency for scenario '{}' ({})".format(
                    result['title'], agg
                ),
                registry=registry,
            )
            latency.set(result['latency'][agg])

        # Throughput.
        throughput = prometheus_client.Gauge(
            'benchmarks_e2e_{}_throughput_rps'.format(benchmark_id),
            "E2E benchmark request throughput (rq / sec) for scenario '{}'".format(
                result['title']
            ),
            registry=registry,
        )
        throughput.set(result['throughput']['throughput_per_sec'])

        print(
            "{title}: avg latency {latency[avg]} ms, "
            "throughput {throughput[throughput_per_sec]} rq / sec".format(**result)
        )

    return process.wait() != 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=None)
    parser.add_argument('--crate', type=str, action='append',
                        default=[],
                        help="Benchmark specific crate (can be specified multiple times)")
    parser.add_argument('--e2e', action='store_true',
                        help="Run end-to-end benchmarks")
    parser.add_argument('--prometheus-host', type=str,
                        default=os.environ.get('BENCHMARKS_PROMETHEUS_HOST', None),
                        help="Prometheus host:port for pushing results to")
    args = parser.parse_args()

    have_errors = False
    registry = prometheus_client.CollectorRegistry()

    # Run crate benchmarks.
    if args.crate:
        print("Running per-crate benchmarks...")

        for crate in args.crate:
            if benchmark_crate(crate, registry):
                have_errors = True

        print("Crate benchmarks done.")

    # Run end-to-end benchmarks.
    if args.e2e:
        print("Running end-to-end benchmarks...")

        if benchmark_e2e(registry):
            have_errors = True

        print("End-to-end benchmarks done.")

    # Push metrics to Prometheus push gateway.
    if args.prometheus_host:
        print("Pushing to Prometheus ({})...".format(args.prometheus_host))
        prometheus_client.push_to_gateway(args.prometheus_host, job='ci', registry=registry)
    else:
        print("Not pushing to Prometheus, here are the metrics:")
        print("===")
        print(prometheus_client.generate_latest(registry).decode('utf8'))
        print("===")

    if have_errors:
        print("ERROR: Some benchmarks completed with errors, aborting.")
        sys.exit(1)
