# Distributed tracing
For tracing we use [Jaeger](https://www.jaegertracing.io) implementation of
the [OpenTracing API](https://opentracing.io/docs) for cross-language
distributed tracing.

## Running with tracing enabled
For tracing, our Go node uses `--tracing.enabled`,
`--tracing.reporter.agent_addr`, and `--tracing.sampler.param` command line
parameters. You can simply uncomment those in the [config file](../configs/single_node.yml).
Check [the source](../go/ekiden/cmd/common/tracing/tracing.go) for how we
process options and setup tracing.

Rust worker uses `--tracing-enable`, `--tracing-agent-addr`, and
`--tracing-sample-probability` command line parameters. If the Rust worker is
dispatched by the Go node, tracing parameters are automatically obtained
from the Go node. Check [the source](../tracing/src/lib.rs) for details. 

Note: Since the Rust worker is sandboxed, we use the proxy for forwarding trace
messages externally: the internal address `127.0.0.1:6831` is forwarded to
Go-created socket `/jaeger-proxy.sock` which forwards to the provided Jaeger
agent address.

## Connecting to a Jaeger agent
Enabling tracing in the programs cause them to act as Jaeger
"clients", which connect to an agent.

### Local testing
You can trace locally by the Jaeger's all-in-one docker container. The  
following will create a Jaeger docker container named `jaeger` and connect it
 to your development container with a bridge network:

```sh
# Publishing port 16686 below is for the web UI.
# Jaeger agent's UDP port 6831 is already accessible.
docker run -d -p 127.0.0.1:16686:16686 --name jaeger jaegertracing/all-in-one:latest
docker network create jaegerbridge
docker network connect jaegerbridge jaeger
# Substitute the name of your development container below!
docker network connect jaegerbridge ekiden-ffffffffffffffff
```

Then, pass `--tracing.enable`, `--tracing.reporter.agent_addr jaeger:6831`, and 
`--tracing-sample-probability 1.0` to our Go node to generate and store all
reported traces.

### Testnet
Similarly, you can configure programs on the testnet by making a release of the
Jaeger Helm chart. Enable tracing, instruct the programs to connect to the agent
service, and set the sampling probability (e.g. 0.1% to reduce load).

## How to look at the traces

### Local testing
Run the ekiden node with the specified runtime (e.g. `simple-keyvalue` runtime),
run a client (e.g. `simple-keyvalue` client), and visit http://127.0.0.1:16686/
with the web browser. There should two services on the left:
- `ekiden-node` which corresponds to our Go node, and
- `ekiden-worker` which corresponds to our Rust worker.

By clicking "Find Traces" button below, on the right you will see all operations
and their spans corresponding to the selected service.

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
See [OpenTracing's specification](https://github.com/opentracing/specification/blob/master/specification.md)
on what "spans" are in tracing. To obtain a _span context_ to correlate your new
span with a trace, you either:

* Pass around a span context to different functions.
* _Inject_ them into RPC messages and _extract_ them.

To start a new trace, get the global tracer and create a new span with
`ekiden_tracing::get_tracer().span(...)` in Rust, and
`opentracing.GlobalTracer().StartSpan(...)` in Go.

To create a new "child" or "follows from" span, pass the parent span's context.
In Go, you pass it by calling `opentracing.ChildOf()` in the `StartSpan()`
function.
```go
span := opentracing.StartSpan(ctx, "storage-memory-lock-set", opentracing.Tag{Key: "ekiden.storage_key", Value: key}, opentracing.ChildOf(parentSpan.Context()))
```

Note: Using the `StartSpanFromContext()` is not the preferred way anymore since
the immutable node's context is used in various places and you should not
replace it each time you make a new span.

In Rust, the preferred way is by taking the parent span's handle:
```rust
let span = parent_span.handle().child("call_contract_batch_enclave", |opts| opts.start());
```

Optionally, add tags, logs, and references to the span. See [OpenTracing's
semantic conventions](https://github.com/opentracing/specification/blob/master/semantic_conventions.md)
on how to represent standard information. For more information on how to add
these, see Rust's `rustracing` [reference](https://docs.rs/rustracing/0.1.7/rustracing/span/struct.Span.html) 
and Go's `opentracing-go` [reference](https://godoc.org/github.com/opentracing/opentracing-go#Span).

Note: For Rust, we use [own fork](https://github.com/oasislabs/rustracing_jaeger.git)
of `rustracing_jaeger` crate which contains a fix for connecting to the agent on
IP other than localhost. This issue has been reported [here](https://github.com/sile/rustracing_jaeger/issues/10).

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
