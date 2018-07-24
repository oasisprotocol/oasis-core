# How to look at the metrics

1. Run the compute node with the metrics serving enabled, by passing a command line arguments like `--prometheus-metrics-addr=0.0.0.0:9091 --prometheus-mode pull` to specify an address from which to serve them.

2. Run Prometheus by running (on host):

```
scripts/prometheus-dev.py \
  --config path-to-prometheus.yml
```

The script starts a Prometheus docker container and connects both (Ekiden & Prometheus) containers to a common network. The Ekiden container is accessible on: `ekiden` address (via docker network alias).
Example of a base `prometheus.yml` file (assumes compute node is exposing metrics on port 9091):

```
scrape_configs:
  - job_name: 'ekiden'
    scrape_interval: 5s

    static_configs:
      - targets: ['ekiden:9091']
        labels:
          group: 'development'
```

3. Open Prometheus and look at [graphs](https://prometheus.io/docs/prometheus/latest/getting_started/#using-the-graphing-interface) or something. The metrics trace in this PR are listed below.

## Prometheus push mode

Prometheus also supports [push mode](https://prometheus.io/docs/instrumenting/pushing/) where clients (instead of exposing an endpoint to for Prometheus to scrape) can push metrics to the prometheus [pushgateway](https://github.com/prometheus/pushgateway).
This will be useful when we will have an always running `pushgateway` on the test stack. For now you can still use it locally following the instructions bellow.

### Start compute node in prometheus 'push' mode

1. Run the compute node by passing following arguments:
- `--prometheus-mode push // starts periodically pushing metrics to the address specified by 'prometheus-metrics-addr'`
- `--prometheus-metrics-addr // url pointing to prometheus pushgateway`
- `--prometheus-push-job-name job-name-label // in 'push' mode this has be specified by the clent`
- `--prometheus-push-instance-label instance-label // same as above`
- `--prometheus-push-interval 60 // optional, time interval (in seconds) for pushing metrics (default 5)`

2. When developing you can use `scripts/prometheus-dev.py` to start both pushgateway docker container and prometheus docker container.

### Development setup for 'push' mode
1. Use the following `prometheus.yml` which will scrape `pushgateway` for metrics.

```
scrape_configs:
  - job_name: 'ekiden'
    scrape_interval: 5s

    static_configs:
      - targets: ['pushgateway:9091']
        labels:
          group: 'development'
```

2. Start prometheus and pushgateway via `prometheus-dev.py` script (on host):

```
$ scripts/prometheus-dev.py --config /path/to/prometheus.yml --push-gateway
```

Starts prometheus and pushgateway instances both connected to the same docker network. Also connects running Ekiden container to the same network. Pushgateway is accessible on the docker network at: `prom-push:9091`.

3. Start compute node setup to push prometheus metrics

```
cargo run -p ekiden-compute -- \
    --time-source-notifier system \
    --entity-ethereum-address 0000000000000000000000000000000000000000 \
    --no-persist-identity \
    --prometheus-metrics-addr pushgateway:9091 \
    --prometheus-mode push \
    --prometheus-push-job-name "ekiden-example" \
    --prometheus-push-instance-label "ekiden-dev-instance" \
    target/enclave/token.so
```


# Metrics
## From GRPC handlers
* `reqs_received` (counter): Incremented in each request.
* `req_time_client` (histogram): Time spent by grpc thread handling a request.

## From worker thread
* `reqs_batches_started` (counter): Incremented in each batch of requests.
* `req_time_batch` (histogram): Time spent by worker thread in an entire batch of requests.
* `req_time_enclave` (histogram): Time spent by worker thread in a single request.
* `consensus_get_time` (histogram): Time spent getting state from consensus.
* `consensus_set_time` (histogram): Time spent setting state in consensus.

# How to add Prometheus metrics to your own processes
1. Add the `prometheus` package as a dependency and declare `#[macro_use] extern crate prometheus`.
2. When you initialize, use the macros `register_counter!(name, help)` [et al.](https://docs.rs/prometheus/0.3.10/prometheus/#macros), which (i) create a metric object and *register* it globally with the prometheus package.
3. In the code to be instrumented, manipulate those metric objects. For example, you might call `.inc()` on a [Counter](https://docs.rs/prometheus/0.3.10/prometheus/struct.Counter.html).
4. Expose the registered metrics over an HTTP server under the path `/metrics`. See [instrumentation.rs](../compute/src/instrumentation.rs#L95-L105) for how I've done it in the compute node with hyper.
