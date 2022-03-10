// Package cmd implements the commands for the test-runner executable.
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	nodeCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	nodeFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd/cmp"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	cfgConfigFile       = "config"
	cfgLogNoStdout      = "log.no_stdout"
	cfgNumRuns          = "num_runs"
	cfgParallelJobCount = "parallel.job_count"
	cfgParallelJobIndex = "parallel.job_index"
)

var (
	rootCmd = &cobra.Command{
		Use:     "oasis-test-runner",
		Short:   "Oasis Test Runner",
		Version: version.SoftwareVersion,
		RunE:    runRoot,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "List registered scenarios",
		Run:   runList,
	}

	cfgFile string
	numRuns int

	oasisTestRunnerCollectors = []prometheus.Collector{
		metrics.UpGauge,
	}

	pusher              *push.Pusher
	oasisTestRunnerOnce sync.Once
)

// RootCmd returns the root command's structure that will be executed, so that
// it can be used to alter the configuration and flags of the command.
//
// Note: `Run` is pre-initialized to the main entry point of the test harness,
// and should likely be left un-altered.
func RootCmd() *cobra.Command {
	return rootCmd
}

// Execute spawns the main entry point after handing the config file.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// RegisterNondefault adds a scenario to the runner.
func RegisterNondefault(s scenario.Scenario) error {
	err := common.RegisterScenario(s, false)
	if err != nil {
		return fmt.Errorf("RegisterNondefault: error registering nondefault scenario: %w", err)
	}

	RegisterScenarioParams(strings.ToLower(s.Name()), s.Parameters())

	return nil
}

// RegisterScenarioParams registers parameters for a given scenario as string
// slices regardless of actual type.
//
// Later we combine specific parameter sets and execute scenarios with all
// parameter combinations.
func RegisterScenarioParams(name string, p *env.ParameterFlagSet) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	p.VisitAll(func(f *flag.Flag) {
		fs.StringSlice(name+"."+f.Name, []string{f.Value.String()}, f.Usage)
	})
	rootCmd.Flags().AddFlagSet(fs)
	_ = viper.BindPFlags(fs)
}

// parseScenarioParams parses --<scenario_name>.<key1>=<val1>,<val2>... flags
// combinations, clones provided proto-scenarios, and populates them so that
// each scenario instance has a unique parameter set.
// Returns a mapping: scenario name -> list of scenario instances.
// NOTE: Golang maps are unordered so ordering of scenarios is not preserved.
func parseScenarioParams(toRun []scenario.Scenario) (map[string][]scenario.Scenario, error) {
	scListsToRun := make(map[string][]scenario.Scenario)
	for _, sc := range toRun {
		zippedParams := make(map[string][]string)
		sc.Parameters().VisitAll(func(f *flag.Flag) {
			// Default to parameter values that were registered as defaults for
			// this particular scenario and parameter combination.
			zippedParams[f.Name] = viper.GetStringSlice(
				fmt.Sprintf(common.ScenarioParamsMask, sc.Name(), f.Name),
			)

			// Use parameter values that very explicitly set for a given
			// (generalized) scenario and parameter combination.
			// NOTE: Parameter values for more specific (generalized) scenario
			// have preference over more generalized ones.
			for _, genName := range generalizedScenarioName(sc.Name()) {
				paramName := fmt.Sprintf(common.ScenarioParamsMask, genName, f.Name)
				if viper.IsSet(paramName) {
					zippedParams[f.Name] = viper.GetStringSlice(paramName)
					break
				}
			}
		})

		parameterSets := computeParamSets(zippedParams, map[string]string{})

		// For each parameter set combination, clone a scenario and apply the
		// provided parameter values.
		for _, paramSet := range parameterSets {
			sCloned := sc.Clone()
			for param, val := range paramSet {
				if err := sCloned.Parameters().Set(param, val); err != nil {
					return nil, fmt.Errorf("parseScenarioParams: error setting viper parameter: %w", err)
				}
			}
			scListsToRun[sc.Name()] = append(scListsToRun[sc.Name()], sCloned)
		}

		// Scenario has no parameters (incl. generalized ones) defined, keep
		// original scenario.
		if len(parameterSets) == 0 {
			scListsToRun[sc.Name()] = []scenario.Scenario{sc}
		}
	}

	return scListsToRun, nil
}

// generalizedScenarioNames returns list of generalized scenario names from the
// original name to most general name.
func generalizedScenarioName(name string) []string {
	dirs := strings.Split(name, "/")
	if len(dirs) == 1 {
		return []string{name}
	}
	subNames := generalizedScenarioName(strings.Join(dirs[0:len(dirs)-1], "/"))
	return append([]string{name}, subNames...)
}

// computeParamSets recursively combines a map of string slices into all possible key=>value parameter sets.
func computeParamSets(zp map[string][]string, ps map[string]string) []map[string]string {
	// Recursion stops when zp is empty. Append ps to result set.
	if len(zp) == 0 {
		if len(ps) == 0 {
			return []map[string]string{}
		}

		psCloned := map[string]string{}
		for k, v := range ps {
			psCloned[k] = v
		}
		return []map[string]string{psCloned}
	}

	rps := []map[string]string{}

	// Take first element from cloned zp and do recursion deterministically.
	var zpKeys []string
	for k := range zp {
		zpKeys = append(zpKeys, k)
	}
	sort.Strings(zpKeys)

	zpCloned := map[string][]string{}
	for _, k := range zpKeys[1:] {
		zpCloned[k] = zp[k]
	}
	// Hack: Empty string slice for parameter value is invalid. Use empty string value instead.
	if len(zp[zpKeys[0]]) == 0 {
		zp[zpKeys[0]] = []string{""}
	}
	for _, v := range zp[zpKeys[0]] {
		ps[zpKeys[0]] = v
		rps = append(rps, computeParamSets(zpCloned, ps)...)
	}

	return rps
}

// Register adds a scenario to the runner and the default scenarios list.
func Register(s scenario.Scenario) error {
	if err := common.RegisterScenario(s, true); err != nil {
		return fmt.Errorf("Register: error registering nondefault scenario: %w", err)
	}

	RegisterScenarioParams(strings.ToLower(s.Name()), s.Parameters())

	return nil
}

func initRootEnv(cmd *cobra.Command) (*env.Env, error) {
	// Initialize the root dir.
	rootDir := env.GetRootDir()
	if err := rootDir.Init(cmd); err != nil {
		return nil, err
	}
	env := env.New(rootDir)

	var ok bool
	defer func() {
		if !ok {
			env.Cleanup()
		}
	}()

	var logFmt logging.Format
	if err := logFmt.Set(viper.GetString(common.CfgLogFmt)); err != nil {
		return nil, fmt.Errorf("root: failed to set log format: %w", err)
	}

	var logLevel logging.Level
	if err := logLevel.Set(viper.GetString(common.CfgLogLevel)); err != nil {
		return nil, fmt.Errorf("root: failed to set log level: %w", err)
	}

	// Initialize logging.
	logFile := filepath.Join(env.Dir(), "test-runner.log")
	w, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("root: failed to open log file: %w", err)
	}

	var logWriter io.Writer = w
	if !viper.GetBool(cfgLogNoStdout) {
		logWriter = io.MultiWriter(os.Stdout, w)
	}
	if err := logging.Initialize(logWriter, logFmt, logLevel, nil); err != nil {
		return nil, fmt.Errorf("root: failed to initialize logging: %w", err)
	}

	ok = true
	return env, nil
}

func runRoot(cmd *cobra.Command, args []string) error { // nolint: gocyclo
	cmd.SilenceUsage = true

	if viper.IsSet(metrics.CfgMetricsAddr) {
		oasisTestRunnerOnce.Do(func() {
			prometheus.MustRegister(oasisTestRunnerCollectors...)
		})
	}

	// Initialize the base dir, logging, etc.
	rootEnv, err := initRootEnv(cmd)
	if err != nil {
		return err
	}
	defer rootEnv.Cleanup()
	logger := logging.GetLogger("test-runner")

	// Enumerate requested scenarios.
	toRun := common.GetDefaultScenarios() // Run all default scenarios if not set.
	if scNameRegexes := viper.GetStringSlice(common.CfgScenarioRegex); len(scNameRegexes) > 0 {
		matched := make(map[scenario.Scenario]bool)
		for _, scNameRegex := range scNameRegexes {
			// Make sure the given scenario name regex matches the whole scenario name, not just
			// a substring.
			regex := fmt.Sprintf("^%s$", scNameRegex)

			var anyMatched bool
			for scName, scenario := range common.GetScenarios() {
				var match bool
				match, err = regexp.MatchString(regex, scName)
				if err != nil {
					return fmt.Errorf("root: bad scenario name regexp: %w", err)
				}
				if match {
					matched[scenario] = true
					anyMatched = true
				}
			}
			if !anyMatched {
				logger.Error("no scenario matches regex",
					"scenario_regex", scNameRegex,
				)
				return fmt.Errorf("root: no scenario matches regex: %s\nAvailable scenarios:\n%s",
					scNameRegex, strings.Join(common.GetScenarioNames(), "\n"),
				)
			}
		}
		toRun = nil
		for scenario := range matched {
			toRun = append(toRun, scenario)
		}
	}
	if skipNameRegexes := viper.GetStringSlice(common.CfgScenarioSkipRegex); len(skipNameRegexes) > 0 {
		var newToRun []scenario.Scenario
		for _, skipNameRegex := range skipNameRegexes {
			regex := fmt.Sprintf("^%s$", skipNameRegex)

			for _, v := range toRun {
				var match bool
				match, err = regexp.MatchString(regex, v.Name())
				if err != nil {
					return fmt.Errorf("root: bad skip scenario regexp: %w", err)
				}
				if !match {
					newToRun = append(newToRun, v)
				}
			}
		}
		toRun = newToRun
	}

	// Sort requested scenarios to enable consistent partitioning for parallel
	// job execution.
	sort.Slice(toRun, func(i, j int) bool { return toRun[i].Name() < toRun[j].Name() })

	excludeMap := make(map[string]bool)
	if excludeEnv := os.Getenv("OASIS_EXCLUDE_E2E"); excludeEnv != "" {
		for _, v := range strings.Split(excludeEnv, ",") {
			excludeMap[strings.ToLower(v)] = true
		}
	}

	// Get parallel job execution parameters.
	parallelJobCount := viper.GetInt(cfgParallelJobCount)
	parallelJobIndex := viper.GetInt(cfgParallelJobIndex)
	if parallelJobIndex < 0 || parallelJobIndex >= parallelJobCount {
		return fmt.Errorf(
			"root: invalid value of %s flag: %d (should be in range [0, %d))",
			cfgParallelJobIndex, parallelJobIndex, parallelJobCount,
		)
	}

	// Expand the list of scenarios to run with the passed scenario parameters.
	var toRunExploded map[string][]scenario.Scenario
	toRunExploded, err = parseScenarioParams(toRun)
	if err != nil {
		return fmt.Errorf("root: failed to parse scenario parameters: %w", err)
	}

	// Run all requested scenarios.
	index := 0
	for run := 0; run < numRuns; run++ {
		// Iterate through toRun instead of toRunExploded to preserve scenario
		// ordering.
		for _, sc := range toRun {
			name := sc.Name()
			scs := toRunExploded[name]
			for i, v := range scs {
				// If number of runs is greater than 1 or if there are multiple
				// parameter sets for a scenario, maintain unique scenario
				// datadir by appending unique run ID.
				n := name
				runID := run*len(scs) + i
				if numRuns > 1 || len(scs) > 1 {
					n = fmt.Sprintf("%s/%d", n, runID)
				}

				if index%parallelJobCount != parallelJobIndex {
					logger.Info("skipping scenario (assigned to different parallel job)",
						"scenario", name, "run_id", runID,
					)
					index++
					continue
				}

				if excludeMap[strings.ToLower(v.Name())] {
					logger.Info("skipping scenario (excluded by environment)",
						"scenario", name, "run_id", runID,
					)
					index++
					continue
				}

				logger.Info("running scenario",
					"scenario", name, "run_id", runID,
				)

				childEnv, err := rootEnv.NewChild(n, &env.ScenarioInstanceInfo{
					Scenario:     v.Name(),
					Instance:     filepath.Base(rootEnv.Dir()),
					ParameterSet: v.Parameters(),
					Run:          run,
				})
				if err != nil {
					logger.Error("failed to setup child environment",
						"err", err, "scenario", name, "run_id", runID,
					)
					return fmt.Errorf("root: failed to setup child environment: %w", err)
				}

				// Dump current parameter set to file.
				if err = childEnv.WriteScenarioInfo(); err != nil {
					return err
				}

				// Init per-run prometheus pusher, if metrics are enabled.
				if viper.IsSet(metrics.CfgMetricsAddr) {
					pusher = push.New(viper.GetString(metrics.CfgMetricsAddr), metrics.MetricsJobTestRunner)
					labels := metrics.GetDefaultPushLabels(childEnv.ScenarioInfo())
					for k, v := range labels {
						pusher = pusher.Grouping(k, v)
					}
					pusher = pusher.Gatherer(prometheus.DefaultGatherer)
				}

				if err = doScenario(childEnv, v); err != nil {
					logger.Error("failed to run scenario",
						"err", err,
						"scenario", name,
						"run_id", runID,
					)
					err = fmt.Errorf("root: failed to run scenario: %w", err)
				}

				if cleanErr := doCleanup(childEnv); cleanErr != nil {
					logger.Error("failed to clean up child environment",
						"err", cleanErr,
						"scenario", name,
						"run_id", runID,
					)
					if err == nil {
						err = fmt.Errorf("root: failed to clean up child environment: %w", cleanErr)
					}
				}

				if err != nil {
					return err
				}

				logger.Info("passed scenario",
					"scenario", name, "run_id", runID,
				)

				index++
			}
		}
	}

	return nil
}

func doScenario(childEnv *env.Env, sc scenario.Scenario) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("root: panic caught running scenario: %v: %s", r, debug.Stack())
		}
	}()

	if err = sc.PreInit(childEnv); err != nil {
		err = fmt.Errorf("root: failed to pre-initialize scenario: %w", err)
		return
	}

	var fixture *oasis.NetworkFixture
	if fixture, err = sc.Fixture(); err != nil {
		err = fmt.Errorf("root: failed to initialize network fixture: %w", err)
		return
	}

	// Instantiate fixture if it is non-nil. Otherwise assume Init will do
	// something on its own.
	var net *oasis.Network
	if fixture != nil {
		if net, err = fixture.Create(childEnv); err != nil {
			err = fmt.Errorf("root: failed to instantiate fixture: %w", err)
			return
		}
	}

	// If network is used, enable shorter per-node socket paths, because some
	// datadir for some scenarios exceed the maximum unix socket path length.
	if net != nil {
		net.Config().UseShortGrpcSocketPaths = true
	}

	if err = sc.Init(childEnv, net); err != nil {
		err = fmt.Errorf("root: failed to initialize scenario: %w", err)
		return
	}

	if pusher != nil {
		metrics.UpGauge.Set(1.0)
		if err = pusher.Push(); err != nil {
			err = fmt.Errorf("root: failed to push metrics: %w", err)
			return
		}
	}

	if err = sc.Run(childEnv); err != nil {
		err = fmt.Errorf("root: failed to run scenario: %w", err)
		return
	}

	if pusher != nil {
		metrics.UpGauge.Set(0.0)
		if err = pusher.Push(); err != nil {
			err = fmt.Errorf("root: failed to push metrics: %w", err)
			return
		}
	}

	return
}

func doCleanup(childEnv *env.Env) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("root: panic caught cleaning up scenario: %v, %s", r, debug.Stack())
		}
	}()

	childEnv.Cleanup()

	return
}

func runList(cmd *cobra.Command, args []string) {
	scNames := common.GetScenarioNames()
	switch len(scNames) {
	case 0:
		fmt.Printf("No scenarios are available.\n")
	default:
		fmt.Printf("Available scenarios:\n")

		for _, name := range scNames {
			fmt.Printf("  * %v", name)
			var intro bool
			common.GetScenarios()[name].Parameters().VisitAll(func(f *flag.Flag) {
				if !intro {
					fmt.Printf(" (parameters:")
					intro = true
				}
				fmt.Printf(" %v", f.Name)
			})
			if intro {
				fmt.Printf(")")
			}
			fmt.Printf("\n")
		}
	}
}

func init() {
	nodeCommon.SetBasicVersionTemplate(rootCmd)

	logFmt := logging.FmtLogfmt
	logLevel := logging.LevelWarn

	// Register persistent flags.
	persistentFlags := flag.NewFlagSet("", flag.ContinueOnError)
	persistentFlags.Var(&logFmt, common.CfgLogFmt, "log format")
	persistentFlags.Var(&logLevel, common.CfgLogLevel, "log level")
	persistentFlags.StringSliceP(
		common.CfgScenarioRegex,
		common.CfgScenarioRegexShort,
		nil,
		"regexp patterns matching names of scenarios",
	)
	persistentFlags.StringSlice(
		common.CfgScenarioSkipRegex,
		nil,
		"regexp patterns matching names of scenarios to skip",
	)
	persistentFlags.String(metrics.CfgMetricsAddr, "", "Prometheus address")
	persistentFlags.StringToString(
		metrics.CfgMetricsLabels,
		map[string]string{},
		"override Prometheus labels",
	)
	_ = viper.BindPFlags(persistentFlags)
	rootCmd.PersistentFlags().AddFlagSet(persistentFlags)

	// Register flags.
	rootFlags := flag.NewFlagSet("", flag.ContinueOnError)
	rootFlags.StringVar(&cfgFile, cfgConfigFile, "", "config file")
	rootFlags.Bool(cfgLogNoStdout, false, "do not multiplex logs to stdout")
	rootFlags.Duration(
		metrics.CfgMetricsInterval,
		5*time.Second,
		"metrics push interval for test runner and oasis nodes",
	)
	rootFlags.IntVarP(&numRuns, cfgNumRuns, "n", 1, "number of runs for given scenario(s)")
	rootFlags.Int(cfgParallelJobCount, 1, "(for CI) number of overall parallel jobs")
	rootFlags.Int(cfgParallelJobIndex, 0, "(for CI) index of this parallel job")
	_ = viper.BindPFlags(rootFlags)
	rootCmd.Flags().AddFlagSet(rootFlags)
	rootCmd.Flags().AddFlagSet(env.Flags)
	rootCmd.AddCommand(listCmd)

	cmp.Register(rootCmd)

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
			if err := viper.ReadInConfig(); err != nil {
				nodeCommon.EarlyLogAndExit(err)
			}
		}

		viper.Set(nodeFlags.CfgDebugDontBlameOasis, true)
		viper.Set(nodeFlags.CfgDebugAllowRoot, true)
		viper.Set(nodeCommon.CfgDebugAllowTestKeys, true)
	})
}
