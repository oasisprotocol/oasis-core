package cmp

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/prometheus/client_golang/api"
	prometheusAPI "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd/common"
)

const (
	cfgMetrics                = "metrics"
	cfgMetricsP               = "m"
	cfgMetricsTargetGitBranch = "metrics.target.git_branch"
	cfgMetricsSourceGitBranch = "metrics.source.git_branch"
	cfgMetricsNetDevice       = "metrics.net.device"
)

var (
	cmpCmd = &cobra.Command{
		Use:   "cmp",
		Short: "compare benchmark results of last two batches",
		Long: `cmp connects to prometheus, fetches results of the benchmark batches and
compares them. By default, the most recent batch (source) is fetched and
compared to the pre-last (target). If --metrics.{target|source}.git_branch is
provided, it compares the most recent batches in the corresponding branches.
cmp compares all metrics provided by --metrics parameter and computes ratio
source/target of metric values. If any of the metrics exceeds
max_threshold.<metric>.{avg|max}_ratio or doesn't reach
min_threshold.<metric>.{avg|max}_ratio, ba exits with error code 1.`,
		Run: runCmp,
	}

	allMetrics = map[string]*Metric{
		"time": {
			getter:               getDuration,
			maxThresholdAvgRatio: 1.1,
			maxThresholdMaxRatio: 1.1,
		},
		"du": {
			getter:               getDiskUsage,
			maxThresholdAvgRatio: 1.06,
			maxThresholdMaxRatio: 1.15,
		},
		"io": {
			getter:               getIOWork,
			maxThresholdAvgRatio: 1.2,
			maxThresholdMaxRatio: 1.2,
		},
		"mem": {
			getter:               getRssAnonMemory,
			maxThresholdAvgRatio: 1.1,
			maxThresholdMaxRatio: 1.1,
		},
		"cpu": {
			getter:               getCPUTime,
			maxThresholdAvgRatio: 1.05,
			maxThresholdMaxRatio: 1.05,
		},
		"net": {
			getter: getNetwork,
			// Network stats suffer effects from other processes too and varies.
			maxThresholdAvgRatio: 1.3,
			maxThresholdMaxRatio: 1.3,
		},
	}
	userMetrics []string

	client api.Client

	cmpLogger *logging.Logger
)

// Metric is a base class for getting a specific prometheus metric and required
// thresholds to test.
//
// There is one instance of this struct for each scenario for each metric.
type Metric struct {
	// getter fetches given coarse time series with finer granularity and
	// returns average and maximum values of all runs in the same batch.
	getter func(context.Context, string, *model.SampleStream) (float64, float64, error)

	// maxThresholdAvgRatio is maximum allowed ratio between the average values
	// of source and target batches.
	maxThresholdAvgRatio float64

	// maxThresholdMaxRatio is maximum allowed ratio between the maximum values
	// of source and target batches.
	maxThresholdMaxRatio float64

	// minThresholdAvgRatio is minimum required ratio between the average values
	// of source and target batches.
	minThresholdAvgRatio float64

	// minThresholdMaxRatio is minimum required ratio between the maximum values
	// of source and target batches.
	minThresholdMaxRatio float64
}

// getDuration returns average and maximum running times of the given coarse
// benchmark instance ("oasis_up" metric with minute resolution time series).
func getDuration(
	ctx context.Context,
	scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	instance := string(bi.Metric[metrics.MetricsLabelInstance])

	// Re-fetch the given benchmark instance with second resolution. Each
	// obtained time series corresponds to one run.
	v1api := prometheusAPI.NewAPI(client)
	r := prometheusAPI.Range{
		Start: bi.Values[0].Timestamp.Time().Add(-1 * time.Minute),
		End:   bi.Values[len(bi.Values)-1].Timestamp.Time().Add(time.Minute),
		Step:  time.Second,
	}

	query := fmt.Sprintf("%s %s == 1.0", metrics.MetricUp, bi.Metric.String())
	result, warnings, err := v1api.QueryRange(ctx, query, r)
	if err != nil {
		return 0, 0, fmt.Errorf("error querying Prometheus: %w", err)
	}
	if len(warnings) > 0 {
		cmpLogger.Warn("warnings while querying Prometheus", "warnings", warnings)
	}
	if len(result.(model.Matrix)) == 0 {
		return 0, 0, fmt.Errorf(
			"getDuration: no time series matched scenario: %s and instance: %s",
			scenario, instance,
		)
	}
	// Compute average and max duration of runs.
	// Since we have a second-resolution, each point denotes 1 second of run's
	// uptime. Just count all points and divide them by the number of runs.
	avgDuration := 0.0
	maxDuration := 0.0
	for _, s := range result.(model.Matrix) {
		avgDuration += float64(len(s.Values))
		if maxDuration < float64(len(s.Values)) {
			maxDuration = float64(len(s.Values))
		}
	}
	avgDuration /= float64(len(result.(model.Matrix)))

	return avgDuration, maxDuration, nil
}

// getIOWork returns average and maximum sum of read and written bytes by all
// workers of the given coarse benchmark instance  ("oasis_up" metric).
func getIOWork(
	ctx context.Context,
	scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	readAvg, readMax, err := getSummableMetric(ctx, metrics.MetricDiskReadBytes, scenario, bi)
	if err != nil {
		return 0, 0, err
	}
	writtenAvg, writtenMax, err := getSummableMetric(ctx, metrics.MetricDiskWrittenBytes, scenario, bi)
	if err != nil {
		return 0, 0, err
	}

	return readAvg + writtenAvg, readMax + writtenMax, nil
}

// getDiskUsage returns average and maximum sum of disk usage for all workers of
// the given coarse benchmark instance ("oasis_up" metric).
func getDiskUsage(
	ctx context.Context,
	scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	return getSummableMetric(ctx, metrics.MetricDiskUsageBytes, scenario, bi)
}

// getRssAnonMemory returns average and maximum sum of anonymous resident memory
// for all workers of the given coarse benchmark instance ("oasis_up" metric).
func getRssAnonMemory(
	ctx context.Context,
	scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	return getSummableMetric(ctx, metrics.MetricMemRssAnonBytes, scenario, bi)
}

// getCPUTime returns average and maximum sum of utime and stime for all workers
// of the given coarse benchmark instance ("oasis_up" metric).
func getCPUTime(
	ctx context.Context,
	scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	utimeAvg, utimeMax, err := getSummableMetric(ctx, metrics.MetricCPUUTimeSeconds, scenario, bi)
	if err != nil {
		return 0, 0, err
	}
	stimeAvg, stimeMax, err := getSummableMetric(ctx, metrics.MetricCPUSTimeSeconds, scenario, bi)
	if err != nil {
		return 0, 0, err
	}

	return utimeAvg + stimeAvg, utimeMax + stimeMax, nil
}

// getSummableMetric returns average and maximum sum of metrics for all workers
// of the given coarse benchmark instance ("oasis_up" metric).
func getSummableMetric(
	ctx context.Context,
	metric, scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	instance := string(bi.Metric[metrics.MetricsLabelInstance])

	labels := bi.Metric.Clone()
	// Existing job denotes the "oasis-test-runner" worker only. We want to sum
	// disk space across all workers.
	delete(labels, "job")
	// We will average metric over all runs.
	delete(labels, "run")

	v1api := prometheusAPI.NewAPI(client)

	query := fmt.Sprintf("sum by (run) (%s %s)", metric, labels.String())

	// Fetch value at last recorded time.
	// Some metrics might not be available anymore, if prometheus was shut down.
	// Add one additional minute to capture reported values within the last
	// minute period.
	t := bi.Values[len(bi.Values)-1].Timestamp.Time().Add(time.Minute)

	result, warnings, err := v1api.Query(ctx, query, t)
	if err != nil {
		return 0, 0, fmt.Errorf("error querying Prometheus: %w", err)
	}
	if len(warnings) > 0 {
		cmpLogger.Warn("warnings while querying Prometheus", "warnings", warnings)
	}
	if len(result.(model.Vector)) == 0 {
		return 0, 0, fmt.Errorf(
			"getSummableMetric: no time series matched scenario: %s and instance: %s",
			scenario, instance,
		)
	}

	// Compute average and max values.
	avg := 0.0
	max := 0.0
	for _, s := range result.(model.Vector) {
		avg += float64(s.Value)
		if max < float64(s.Value) {
			max = float64(s.Value)
		}
	}
	avg /= float64(len(result.(model.Vector)))

	return avg, max, nil
}

// getNetwork returns average and maximum amount of network activity for all
// workers of the given coarse benchmark instance ("oasis_up" metric).
func getNetwork(
	ctx context.Context,
	scenario string,
	bi *model.SampleStream,
) (float64, float64, error) {
	instance := string(bi.Metric[metrics.MetricsLabelInstance])

	labels := bi.Metric.Clone()
	// We will group by job to fetch traffic across all workers.
	delete(labels, "job")
	// We will average metric over all runs.
	delete(labels, "run")
	// We will consider traffic from loopback device only.
	labels["device"] = model.LabelValue(viper.GetString(cfgMetricsNetDevice))

	v1api := prometheusAPI.NewAPI(client)
	r := prometheusAPI.Range{
		Start: bi.Values[0].Timestamp.Time().Add(-1 * time.Minute),
		End:   bi.Values[len(bi.Values)-1].Timestamp.Time().Add(time.Minute),
		Step:  time.Second,
	}

	// We store total network traffic values. Compute the difference.
	bytesTotalAvg := map[string]float64{}
	bytesTotalMax := map[string]float64{}
	for _, rxtx := range []string{metrics.MetricNetReceiveBytesTotal, metrics.MetricNetTransmitBytesTotal} {
		query := fmt.Sprintf("(%s %s)", rxtx, labels.String())
		result, warnings, err := v1api.QueryRange(ctx, query, r)
		if err != nil {
			return 0, 0, fmt.Errorf("error querying Prometheus: %w", err)
		}
		if len(warnings) > 0 {
			cmpLogger.Warn("warnings while querying Prometheus", "warnings", warnings)
		}
		if len(result.(model.Matrix)) == 0 {
			return 0, 0, fmt.Errorf(
				"getNetworkMetric: no time series matched scenario: %s and instance: %s",
				scenario, instance,
			)
		}

		// Compute average and max values.
		avg := 0.0
		max := 0.0
		for _, s := range result.(model.Matrix) {
			// Network traffic is difference between last and first reading.
			avg += float64(s.Values[len(s.Values)-1].Value - s.Values[0].Value)
			if max < float64(s.Values[len(s.Values)-1].Value-s.Values[0].Value) {
				max = float64(s.Values[len(s.Values)-1].Value - s.Values[0].Value)
			}
		}
		avg /= float64(len(result.(model.Matrix)))

		bytesTotalAvg[rxtx] = avg
		bytesTotalMax[rxtx] = max
	}

	return (bytesTotalAvg[metrics.MetricNetReceiveBytesTotal] + bytesTotalAvg[metrics.MetricNetTransmitBytesTotal]) / 2.0,
		(bytesTotalMax[metrics.MetricNetReceiveBytesTotal] + bytesTotalMax[metrics.MetricNetTransmitBytesTotal]) / 2.0,
		nil
}

// getCoarseBenchmarkInstances finds time series based on "oasis_up" metric with
// minute resolution for the given scenario and labels ordered from the oldest
// to the most recent ones.
//
// This function is called initially to determine benchmark instances to
// compare. Afterwards, the metric-specific operation fetches time series with
// finer (second) granularity.
//
// NOTE: Due to Prometheus limit, this function fetches time series in the past
// 183 hours only.
func getCoarseBenchmarkInstances(
	ctx context.Context,
	scenario string,
	labels map[string]string,
) (model.Matrix, error) {
	v1api := prometheusAPI.NewAPI(client)
	r := prometheusAPI.Range{
		// XXX: Hardcoded max resolution in Prometheus is 11,000 points or ~183
		// hours with minute resolution.
		Start: time.Now().Add(-183 * time.Hour),
		End:   time.Now(),
		Step:  time.Minute,
	}

	ls := model.LabelSet{
		"job":                        metrics.MetricsJobTestRunner,
		metrics.MetricsLabelScenario: model.LabelValue(scenario),
	}
	for k, v := range labels {
		ls[model.LabelName(k)] = model.LabelValue(v)
	}

	query := fmt.Sprintf("max(%s %s) by (%s) == 1.0",
		metrics.MetricUp, ls.String(), metrics.MetricsLabelInstance,
	)
	result, warnings, err := v1api.QueryRange(ctx, query, r)
	if err != nil {
		cmpLogger.Error("error querying Prometheus", "err", err)
		os.Exit(1)
	}
	if len(warnings) > 0 {
		cmpLogger.Warn("warnings while querying Prometheus", "warnings", warnings)
	}

	// Go through all obtained time series and order them by the timestamp of the first sample.
	sort.Slice(result.(model.Matrix), func(i, j int) bool {
		return result.(model.Matrix)[i].Values[0].Timestamp < result.(model.Matrix)[j].Values[0].Timestamp
	})
	return result.(model.Matrix), nil
}

// instanceNames extracts instance names from given Prometheus time series matrix.
func instanceNames(ts model.Matrix) []string {
	var names []string
	for _, t := range ts {
		names = append(names, instanceName(t))
	}
	return names
}

// instanceName returns the instance name label of the given sample.
func instanceName(s *model.SampleStream) string {
	return string(s.Metric[metrics.MetricsLabelInstance])
}

// fetchAndCompare fetches the given metric from prometheus and compares the
// results.
//
// If metric-specific ratios are exceeded or if there is a problem obtaining
// time series, returns false. Otherwise, returns true.
func fetchAndCompare(
	ctx context.Context,
	m, scenario string,
	sInstance, tInstance *model.SampleStream,
) (succ bool) {
	getMetric := allMetrics[m].getter
	succ = true

	sAvg, sMax, err := getMetric(ctx, scenario, sInstance)
	if err != nil {
		cmpLogger.Error("error fetching source benchmark instance",
			"metric", m,
			"scenario", scenario,
			"instance", instanceName(sInstance),
			"err", err,
		)
		return false
	}

	tAvg, tMax, err := getMetric(ctx, scenario, tInstance)
	if err != nil {
		cmpLogger.Error("error fetching target scenario instance",
			"metric", m,
			"scenario", scenario,
			"instance", instanceName(sInstance),
			"err", err,
		)
		return false
	}

	// Compare average and max metric values and log error(s) if they exceed or
	// don't reach required ratios.
	maxAvgRatio := allMetrics[m].maxThresholdAvgRatio
	maxMaxRatio := allMetrics[m].maxThresholdMaxRatio
	minAvgRatio := allMetrics[m].minThresholdAvgRatio
	minMaxRatio := allMetrics[m].minThresholdMaxRatio
	cmpLogger.Info("obtained average ratio",
		"metric", m,
		"scenario", scenario,
		"source_avg", sAvg,
		"target_avg", tAvg,
		"ratio", sAvg/tAvg,
	)
	if maxAvgRatio != 0 && sAvg/tAvg > maxAvgRatio {
		cmpLogger.Error("average metric value exceeds max allowed ratio",
			"metric", m,
			"scenario", scenario,
			"source_avg", sAvg,
			"target_avg", tAvg,
			"ratio", sAvg/tAvg,
			"max_allowed_avg_ratio", maxAvgRatio,
		)
		succ = false
	}
	if minAvgRatio != 0 && sAvg/tAvg < minAvgRatio {
		cmpLogger.Error("average metric value doesn't reach min required ratio",
			"metric", m,
			"scenario", scenario,
			"source_avg", sAvg,
			"target_avg", tAvg,
			"ratio", sAvg/tAvg,
			"min_required_avg_ratio", minAvgRatio,
		)
		succ = false
	}
	cmpLogger.Info("obtained max ratio",
		"metric", m,
		"scenario", scenario,
		"source_max", sMax,
		"target_max", tMax,
		"ratio", sMax/tMax,
	)
	if maxMaxRatio != 0 && sMax/tMax > maxMaxRatio {
		cmpLogger.Error("maximum metric value exceeds max ratio",
			"metric", m,
			"scenario", scenario,
			"source_max", sMax,
			"target_max", tMax,
			"ratio", sMax/tMax,
			"max_allowed_max_ratio", maxMaxRatio,
		)
		succ = false
	}
	if minMaxRatio != 0 && sMax/tMax < maxMaxRatio {
		cmpLogger.Error("maximum metric value doesn't reach min required ratio",
			"metric", m,
			"scenario", scenario,
			"source_max", sMax,
			"target_max", tMax,
			"ratio", sMax/tMax,
			"min_required_max_ratio", maxMaxRatio,
		)
		succ = false
	}

	return
}

func initCmpLogger() error {
	var logFmt logging.Format
	if err := logFmt.Set(viper.GetString(common.CfgLogFmt)); err != nil {
		return fmt.Errorf("root: failed to set log format: %w", err)
	}

	var logLevel logging.Level
	if err := logLevel.Set(viper.GetString(common.CfgLogLevel)); err != nil {
		return fmt.Errorf("root: failed to set log level: %w", err)
	}

	if err := logging.Initialize(os.Stdout, logFmt, logLevel, nil); err != nil {
		return fmt.Errorf("root: failed to initialize logging: %w", err)
	}

	cmpLogger = logging.GetLogger("cmd/cmp")

	return nil
}

func runCmp(cmd *cobra.Command, args []string) {
	if err := initCmpLogger(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var err error
	client, err = api.NewClient(api.Config{
		Address: viper.GetString(metrics.CfgMetricsAddr),
	})
	if err != nil {
		cmpLogger.Error("error creating client", "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	scenarios := viper.GetStringSlice(common.CfgScenarioRegex)
	if len(scenarios) == 0 {
		for _, s := range common.GetDefaultScenarios() {
			scenarios = append(scenarios, s.Name())
		}
	}
	succ := true
	for _, sc := range scenarios {
		srcLabels, tgtLabels := map[string]string{}, map[string]string{}
		if viper.IsSet(cfgMetricsSourceGitBranch) {
			srcLabels[metrics.MetricsLabelGitBranch] = viper.GetString(cfgMetricsSourceGitBranch)
		}
		if viper.IsSet(cfgMetricsTargetGitBranch) {
			tgtLabels[metrics.MetricsLabelGitBranch] = viper.GetString(cfgMetricsTargetGitBranch)
		}

		// Set other required Prometheus labels, if passed.
		// TODO: Integrate scenario parameters and parameter set combinations if
		// multiple values are provided like we do in oasis-test-runner.
		for k, v := range viper.GetStringMapString(metrics.CfgMetricsLabels) {
			srcLabels[k] = v
			tgtLabels[k] = v
		}

		srcScInstances, err := getCoarseBenchmarkInstances(ctx, sc, srcLabels)
		if err != nil {
			cmpLogger.Error("error querying for source scenario instances", "err", err)
			os.Exit(1)
		}
		srcScNames := instanceNames(srcScInstances)
		tgtScInstances, err := getCoarseBenchmarkInstances(ctx, sc, tgtLabels)
		if err != nil {
			cmpLogger.Error("error querying for target scenario instances", "err", err)
			os.Exit(1)
		}
		tgtScNames := instanceNames(tgtScInstances)

		if len(srcScNames) == 0 {
			cmpLogger.Info(
				"scenario does not have any source benchmark instances to compare, ignoring",
				"scenario", sc,
			)
			continue
		}
		if len(tgtScNames) == 0 {
			cmpLogger.Info(
				"scenario does not have any target benchmark instances to compare, ignoring",
				"scenario", sc,
			)
			continue
		}

		var srcInstance, tgtInstance *model.SampleStream
		if srcScNames[len(srcScNames)-1] != tgtScNames[len(tgtScNames)-1] {
			// Benchmark instances differ e.g. because of different gitBranch.
			srcInstance = srcScInstances[len(srcScInstances)-1]
			tgtInstance = tgtScInstances[len(tgtScInstances)-1]
		} else {
			// Last benchmark instances are equal, pick the pre-last one from
			// the target instances.
			if len(tgtScNames) < 2 {
				cmpLogger.Info("scenario only has one benchmark instance, ignoring",
					"scenario", sc,
					"source_instances", srcScNames,
					"target_instances", tgtScNames,
				)
				continue
			}
			srcInstance = srcScInstances[len(srcScInstances)-1]
			tgtInstance = tgtScInstances[len(tgtScInstances)-2]
		}
		cmpLogger.Info("obtained source and target instance",
			"scenario", sc,
			"source_instance", instanceName(srcInstance),
			"target_instance", instanceName(tgtInstance),
		)

		for _, m := range userMetrics {
			// Don't put succ = succ && f oneliner here, because f won't get
			// executed once succ = false.
			fSucc := fetchAndCompare(ctx, m, sc, srcInstance, tgtInstance)
			succ = succ && fSucc
		}
	}

	if !succ {
		os.Exit(1)
	}

	defer cancel()
}

// Register oasis-test-runner cmp sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	cmpFlags := flag.NewFlagSet("", flag.ContinueOnError)

	var metricNames []string
	for k := range allMetrics {
		metricNames = append(metricNames, k)
		cmpFlags.Float64Var(
			&allMetrics[k].maxThresholdAvgRatio,
			fmt.Sprintf("max_threshold.%s.avg_ratio", k),
			allMetrics[k].maxThresholdAvgRatio,
			fmt.Sprintf("maximum allowed ratio between average %s metrics", k),
		)
		cmpFlags.Float64Var(
			&allMetrics[k].maxThresholdMaxRatio,
			fmt.Sprintf("max_threshold.%s.max_ratio", k),
			allMetrics[k].maxThresholdMaxRatio,
			fmt.Sprintf("maximum allowed ratio between maximum %s metrics", k),
		)
		cmpFlags.Float64Var(
			&allMetrics[k].minThresholdAvgRatio,
			fmt.Sprintf("min_threshold.%s.avg_ratio", k),
			allMetrics[k].minThresholdAvgRatio,
			fmt.Sprintf("minimum required ratio between average %s metrics", k),
		)
		cmpFlags.Float64Var(
			&allMetrics[k].minThresholdMaxRatio,
			fmt.Sprintf("min_threshold.%s.max_ratio", k),
			allMetrics[k].minThresholdMaxRatio,
			fmt.Sprintf("minimum required ratio between maximum %s metrics", k),
		)
	}
	cmpFlags.StringSliceVarP(&userMetrics, cfgMetrics, cfgMetricsP, metricNames, "metrics to compare")

	cmpFlags.String(
		cfgMetricsSourceGitBranch,
		"",
		"(optional) git_branch label for the source benchmark instance",
	)
	cmpFlags.String(
		cfgMetricsTargetGitBranch,
		"",
		"(optional) git_branch label for the target benchmark instance",
	)
	cmpFlags.String(cfgMetricsNetDevice, "lo", "network device traffic to compare")

	_ = viper.BindPFlags(cmpFlags)
	cmpCmd.Flags().AddFlagSet(cmpFlags)

	parentCmd.AddCommand(cmpCmd)
}
