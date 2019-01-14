# Distributed tracing
We've selected the OpenTracing API for adding distributed tracing.
They have documentation about the philosophy and data model online:
http://opentracing.io/documentation/.
We have selected Jaeger https://www.jaegertracing.io/ as the backend.

## Running with tracing enabled
For Rust programs (compute node and dummy node), pass
`--tracing-enable` (see the `tracing/src/lib.rs` package for how we
process these common options).
For the Go dummy node, pass `--tracing.enabled` (see
`go/ekiden/cmd/tracing.go` for how we process these options). Tracing
by default samples at 0.1%, and you can set this with other command
line options.

## Connecting to a Jaeger agent
Enabling tracing in the programs cause them to act as Jaeger
"clients," which connect to an agent on the same machine.
Although due to containerization, we usually don't make the agent
available through the loopback interface.
You have to tell the programs how to communicate with the agent.

### Local testing
You can test locally by running Jaeger's all-in-one container and
connecting it to your development container with a bridge network:

```sh
# the publish below publishes the query UI
docker run -d -p 127.0.0.1:16686:16686 --name jaeger jaegertracing/all-in-one:latest
docker network create jaegerbridge
docker network connect jaegerbridge jaeger
# substitute the name of your development container below
docker network connect jaegerbridge ekiden-ffffffffffffffff
```

Instruct the programs to connect by passing `--tracing-agent-addr
jaeger:6831` for Rust programs or `--tracing.reporter.agent-addr
jaeger:6831` for the Go dummy node.

### Testnet
You can configure programs on the testnet by making a release of the
Jaeger Helm chart.

Instruct the programs to connect to the agent service.

## How to look at the traces

### Local testing
Open http://127.0.0.1:16686/ in your browser.

### Testnet
Configure an ingress to the query service and open that in your
browser.

Or, if don't want to set up an ingress, then follow these steps to
forward your browser traffic to the query service:

1. Forward traffic from your host computer to the bridge network in
   the ops shell container. Do this by adding `-p
   127.0.0.1:16686:16687` to the command line that `make shell` would
   run.
2. Forward traffic from the container's bridge network interface to
   its loopback interface. Do this by running `apt-get install socat`
   and `socat TCP-LISTEN:16687,fork TCP:127.0.0.1:16686 &`.
3. Forward traffic from the container's loopback interface to the
   query service. Do this by running
   `kubectl port-forward services/jaeger-query 16686:80 &`.

Then open http://127.0.0.1:16686/ in your browser.

Aside:
A change to Kubernetes
([issue](https://github.com/kubernetes/kubernetes/issues/43962),
[PR](https://github.com/kubernetes/kubernetes/pull/46517)) is under
development that will allow `kubectl port-forward` to listen on
interfaces other than loopback, which would make the `socat` step
unnecessary.

## Adding tracing
See OpenTracing's specification
https://github.com/opentracing/specification/blob/master/specification.md
on what "spans" are in tracing.

Obtain a _span context_ to correlate your new span with a trace.
You can:

* Pass around a span context to different functions.
* _Inject_ them into RPC messages and _extract_ them.

Use the span context to create a new "child" or "follows from" span,
with, for example, `rustracing_jaeger::span::SpanHandle::child(...)`
in Rust and `opentracing.StartSpanFromContext(...)` in Go.

If you want to start a new trace, get the global tracer and sample a
the first span, with `ekiden_tracing::get_tracer().span(...)` in Rust
and `opentracing.GlobalTracer().StartSpan(...)` in Go.

Add tags, logs, and references to the span.
See OpenTracing's semantic conventions
https://github.com/opentracing/specification/blob/master/semantic_conventions.md
on how to represent standard information.
See the library reference, `rustracing`
https://docs.rs/rustracing/0.1.7/rustracing/span/struct.Span.html for
Rust and `opentracing-go`
https://godoc.org/github.com/opentracing/opentracing-go#Span for Go,
for how to add these.

# Prometheus metrics

## How to look at the metrics

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
    target/enclave/simple-keyvalue.so
```


## Metrics
### From GRPC handlers
* `reqs_received` (counter): Incremented in each request.
* `req_time_client` (histogram): Time spent by grpc thread handling a request.

### From worker thread
* `reqs_batches_started` (counter): Incremented in each batch of requests.
* `req_time_batch` (histogram): Time spent by worker thread in an entire batch of requests.
* `req_time_enclave` (histogram): Time spent by worker thread in a single request.
* `consensus_get_time` (histogram): Time spent getting state from consensus.
* `consensus_set_time` (histogram): Time spent setting state in consensus.

## How to add Prometheus metrics to your own processes
1. Add the `prometheus` package as a dependency and declare `#[macro_use] extern crate prometheus`.
2. When you initialize, use the macros `register_counter!(name, help)` [et al.](https://docs.rs/prometheus/0.3.10/prometheus/#macros), which (i) create a metric object and *register* it globally with the prometheus package.
3. In the code to be instrumented, manipulate those metric objects. For example, you might call `.inc()` on a [Counter](https://docs.rs/prometheus/0.3.10/prometheus/struct.Counter.html).
4. Expose the registered metrics over an HTTP server under the path `/metrics`. See [instrumentation.rs](../compute/src/instrumentation.rs#L95-L105) for how I've done it in the compute node with hyper.
