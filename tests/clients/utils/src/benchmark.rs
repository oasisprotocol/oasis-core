use std::sync::mpsc::channel;
use std::sync::Arc;

use histogram::Histogram;
use serde_json;
use threadpool::ThreadPool;
use time;

/// Client factory.
pub trait ClientFactory: Send + Sync + 'static {
    type Client: Send + Sync;

    /// Create a new client instance.
    fn create(&self) -> Self::Client;
}

impl<Client, F> ClientFactory for F
where
    Client: Send + Sync,
    F: Send + Sync + 'static + Fn() -> Client,
{
    type Client = Client;

    fn create(&self) -> Client {
        (*self)()
    }
}

/// Benchmark helper.
pub struct Benchmark<Factory: ClientFactory> {
    /// Number of scenario runs.
    runs: usize,
    /// Workers.
    pool: ThreadPool,
    /// Client factory.
    client_factory: Arc<Factory>,
}

/// Benchmark results for a single thread.
///
/// All time values are in nanoseconds.
#[derive(Debug, Clone, Default)]
pub struct BenchmarkResult {
    /// Amount of time taken for client initialization. This includes the time it
    /// takes to establish a secure channel.
    pub client_initialization: u64,
    /// A vector of pairs `(start_time, end_time)` containing timestamps of when the
    /// scenario has started and when it has finished.
    pub scenario: Vec<(u64, u64)>,
    /// Amount of time taken for client dropping. This includes the
    /// time it takes to close a secure channel.
    pub client_drop: u64,
}

/// Set of benchmark results for all runs.
pub struct BenchmarkResults {
    /// Number of runs.
    pub runs: usize,
    /// Benchmark results from non-panicked individual runs.
    pub results: Vec<BenchmarkResult>,
    /// The number of threads the experiment was run with.
    pub threads: usize,
}

/// Benchmark results output format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
}

/// Latency results.
#[derive(Debug, Serialize)]
pub struct LatencyResults {
    /// 50th percentile latency (in ms).
    p50: u64,
    /// 90th percentile latency (in ms).
    p90: u64,
    /// 99th percentile latency (in ms).
    p99: u64,
    /// 99.9th percentile latency (in ms).
    p999: u64,
    /// Minimum latency (in ms).
    min: u64,
    /// Average latency (in ms).
    avg: u64,
    /// Maximum latency (in ms).
    max: u64,
    /// Standard deviation of latency (in ms).
    std_dev: u64,
}

/// Throughput results.
#[derive(Debug, Serialize)]
pub struct ThroughputResults {
    /// Number of requests in the middle 80%.
    middle80_request_count: usize,
    /// Total non-overlapping time taken to do the requests.
    total_nonoverlapping_time: u64,
    /// Request throughput in requests per second.
    throughput_per_sec: f64,
}

/// Aggregated benchmark results.
#[derive(Debug, Serialize)]
pub struct AggregatedBenchmarkResults {
    /// Scenario title.
    title: String,
    /// Number of threads used.
    threads: usize,
    /// Number of requests per thread.
    requests: usize,
    /// Number of non-panicked requests.
    non_panicked_request_count: u64,
    /// Number of panicked requests.
    panicked_request_count: u64,
    /// Latency.
    latency: LatencyResults,
    /// Throughput.
    throughput: ThroughputResults,
}

impl AggregatedBenchmarkResults {
    /// Print aggregated results in text format.
    pub fn print_text(&self) {
        println!("------ {} ------", self.title);
        println!("=== Benchmark Results ===");
        println!("Threads:                   {}", self.threads);
        println!("Requests per thread:       {}", self.requests);
        println!(
            "Non-panicked (npr):        {}",
            self.non_panicked_request_count
        );
        println!("Panicked:                  {}", self.panicked_request_count);

        println!("--- Latency ---");
        println!(
            "Percentiles: p50: {} ms / p90: {} ms / p99: {} ms / p999: {} ms",
            self.latency.p50, self.latency.p90, self.latency.p99, self.latency.p999,
        );
        println!(
            "Min: {} ms / Avg: {} ms / Max: {} ms / StdDev: {} ms",
            self.latency.min, self.latency.avg, self.latency.max, self.latency.std_dev,
        );

        println!("--- Throughput ---");
        println!(
            "Middle 80%:                {} npr",
            self.throughput.middle80_request_count
        );
        println!(
            "Scenario (middle 80%):     {} ms ({} npr / sec)",
            self.throughput.total_nonoverlapping_time, self.throughput.throughput_per_sec,
        );
        println!("");
    }

    /// Print aggregated results in JSON format.
    pub fn print_json(&self) {
        println!("{}", serde_json::to_string(self).unwrap());
    }
}

impl BenchmarkResults {
    /// Show benchmark results in a human-readable form.
    pub fn show(&self, title: &str, format: OutputFormat) {
        // Prepare histograms.
        let mut histogram_scenario = Histogram::new();
        let mut count = 0;

        let mut throughput_runs: Vec<(u64, u64)> = vec![];

        for result in &self.results {
            for &(start, end) in &result.scenario {
                histogram_scenario
                    .increment((end - start) / 1_000_000)
                    .unwrap();

                count += 1;
                throughput_runs.push((start, end));
            }
        }

        // Sort by start timestamp.
        throughput_runs.sort_by(|a, b| a.0.cmp(&b.0));
        // Cut 10% at the beginning and the end.
        let cut_amount = (throughput_runs.len() as f64 * 0.10).floor() as usize;
        let throughput_runs = &throughput_runs[cut_amount..throughput_runs.len() - cut_amount];
        let total_nonoverlapping =
            throughput_runs.last().unwrap().1 - throughput_runs.first().unwrap().0;

        let failures = (self.threads * self.runs) as u64 - count;

        let results = AggregatedBenchmarkResults {
            title: title.into(),
            threads: self.threads,
            requests: self.runs,
            non_panicked_request_count: count,
            panicked_request_count: failures,
            latency: LatencyResults {
                p50: histogram_scenario.percentile(50.0).unwrap(),
                p90: histogram_scenario.percentile(90.0).unwrap(),
                p99: histogram_scenario.percentile(99.0).unwrap(),
                p999: histogram_scenario.percentile(99.9).unwrap(),
                min: histogram_scenario.minimum().unwrap(),
                avg: histogram_scenario.mean().unwrap(),
                max: histogram_scenario.maximum().unwrap(),
                std_dev: histogram_scenario.stddev().unwrap(),
            },
            throughput: ThroughputResults {
                middle80_request_count: throughput_runs.len(),
                total_nonoverlapping_time: total_nonoverlapping / 1_000_000,
                throughput_per_sec: throughput_runs.len() as f64
                    / (total_nonoverlapping as f64 / 1e9),
            },
        };

        match format {
            OutputFormat::Text => {
                results.print_text();
            }
            OutputFormat::Json => {
                results.print_json();
            }
        }
    }
}

/// Helper macro for timing a specific block of code.
macro_rules! time_block {
    ($result:ident, $measurement:ident, $block:block) => {{
        let start = time::precise_time_ns();
        let result = $block;
        $result.$measurement = time::precise_time_ns() - start;

        result
    }};
}

/// Helper to collect into a Vec without redeclaring an item type.
fn collect_vec<I: Iterator>(i: I) -> Vec<I::Item> {
    i.collect()
}

impl<Factory> Benchmark<Factory>
where
    Factory: ClientFactory,
{
    /// Create a new benchmark helper.
    pub fn new(runs: usize, threads: usize, client_factory: Factory) -> Self {
        Benchmark {
            runs: runs,
            pool: ThreadPool::with_name("benchmark-scenario".into(), threads),
            client_factory: Arc::new(client_factory),
        }
    }

    /// Run the given benchmark scenario.
    ///
    /// The `init` function will only be called once and should prepare the
    /// grounds for running scenarios. Then multiple `scenario` invocations
    /// will run in parallel. At the end, the `finalize` function will be
    /// called once.
    ///
    /// Both `init` and `finalize` will be invoked with the number of runs
    /// and the number of threads as the last two arguments.
    pub fn run(
        &self,
        init: Option<fn(&mut Factory::Client, usize, usize)>,
        scenario: fn(&mut Factory::Client),
        finalize: Option<fn(&mut Factory::Client, usize, usize)>,
        verbose: bool,
    ) -> BenchmarkResults {
        // Initialize.
        if verbose {
            println!("Initializing benchmark...");
        }

        let mut client = self.client_factory.create();
        if let Some(init) = init {
            init(&mut client, self.runs, self.pool.max_count());
        }

        if verbose {
            println!(
                "Running benchmark with {} threads, each doing {} requests...",
                self.pool.max_count(),
                self.runs
            );
        }

        let (tx, rx) = channel();
        for _ in 0..self.pool.max_count() {
            let tx = tx.clone();
            let client_factory = self.client_factory.clone();
            let runs = self.runs;

            self.pool.execute(move || {
                let mut result = BenchmarkResult::default();

                // Create the client.
                let mut client =
                    time_block!(result, client_initialization, { client_factory.create() });

                // Run the scenario multiple times.
                for _ in 0..runs {
                    let start = time::precise_time_ns();
                    scenario(&mut client);
                    let end = time::precise_time_ns();

                    result.scenario.push((start, end));
                }

                time_block!(result, client_drop, { drop(client) });

                tx.send(result).unwrap();
            });
        }

        self.pool.join();
        let results = collect_vec(rx.try_iter());

        // Finalize.
        if verbose {
            println!("Finalizing benchmark...");
        }
        let mut client = self.client_factory.create();
        if let Some(finalize) = finalize {
            finalize(&mut client, self.runs, self.pool.max_count());
        }

        // Collect benchmark results.
        BenchmarkResults {
            runs: self.runs,
            results: results,
            threads: self.pool.max_count(),
        }
    }
}
