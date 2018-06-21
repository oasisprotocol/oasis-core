# How to look at the metrics
1. Run the compute node with the metrics serving enabled, by passing a command line argument like `--metrics-addr=0.0.0.0:9091` to specify an address from which to serve them.
2. Run prometheus by running (on host):
```
scripts/prometheus-dev.py \
  --ekiden-name running-ekiden-container-name \
  --config path-to-prometheus.yml
```

The script starts a Prometheus docker container and connects both (ekiden & prometheus) containers to a common network. The ekiden container is accessible on: `ekiden` address (via docker network alias).

Example of a base `prometheus.yml` file (assumes compute node exposing metrics on port 9091):

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

# Prometheus-dev.py

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
