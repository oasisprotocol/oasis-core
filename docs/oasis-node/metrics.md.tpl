# Metrics

`oasis-node` can report a number of metrics to Prometheus server. By default,
no metrics are collected and reported. There are two ways to enable metrics
reporting:

* *Pull mode* listens on given address and waits for Prometheus to scrape the
  metrics.
* *Push mode* regularly pushes metrics to the provided Prometheus push gateway.

## Configuring `oasis-node` in Pull Mode

To run `oasis-node` in *pull mode* set flag `--metrics.mode pull` and provide
the listen address with `--metrics.address`. For example

```
oasis-node --metrics.mode pull --metrics.address localhost:3000
```

Then, add the following segment to your `prometheus.yml` and restart
Prometheus:

```yaml
  - job_name : 'oasis-node'

    scrape_interval: 5s

    static_configs:
      - targets: ['localhost:3000']
```

## Configuring `oasis-node` in Push Mode

First run Prometheus server and Prometheus push gateway. Then run `oasis-node`
in *push mode* by setting flag `--metrics.mode push` and provide:

* push gateway address with `--metrics.address`, and
* push interval with `--metrics.interval`.

For example:

```
oasis-node --metrics.mode push --metrics.address localhost:9091 --metrics.interval 5s
```

## Metrics Reported by `oasis-node`

`oasis-node` reports metrics starting with `oasis_`.

The following metrics are currently reported:

<!-- markdownlint-disable line-length -->

<!--- OASIS_METRICS -->

<!-- markdownlint-enable line-length -->

## Consensus backends

### Metrics Reported by *Tendermint*

When `oasis-node` is configured to use [Tendermint][1] for BFT consensus, all
Tendermint metrics are also reported. Consult
[tendermint-core documentation][2] for a list of reported by Tendermint.

[1]: ../consensus/index.md#tendermint
[2]: https://docs.tendermint.com/master/tendermint-core/metrics.html
