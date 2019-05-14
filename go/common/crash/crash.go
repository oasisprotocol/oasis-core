// Package crash provides a framework for adding probabilistic crash points. The
// package provides a global singleton that can be used to register, configure,
// and trigger crashes.
package crash

import (
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/debug"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/random"
)

// defaultCLIPrefix is the default CLI prefix used to configure crash points in
// viper and cobra.
const defaultCLIPrefix = "debug.crash"

// RandomProvider interface that provides a Float64 random.
type RandomProvider interface {
	Float64() float64
}

// Crasher is a crash controller.
type Crasher struct {
	CrashPointConfig map[string]float64
	CrashMethod      func()
	CLIPrefix        string
	Rand             RandomProvider
	logger           *logging.Logger

	// callerSkip is used by the global crasher instance to determine the caller
	// of the package level `Here` function.
	callerSkip int
}

// CrasherOptions options used to create a new crasher.
type CrasherOptions struct {
	CrashMethod func()
	CLIPrefix   string
	Rand        RandomProvider
	CallerSkip  int
}

func newDefaultRandomProvider() RandomProvider {
	// Seed randomness using time by default.
	return random.NewRand(time.Now().Unix())
}

func defaultCrashMethod() {
	debug.Trap()
}

var crashGlobal *Crasher

func init() {
	crashGlobal = New(CrasherOptions{
		CallerSkip: 1,
		CLIPrefix:  defaultCLIPrefix,
	})
}

// New creates a new crasher.
func New(options CrasherOptions) *Crasher {
	if options.CrashMethod == nil {
		options.CrashMethod = defaultCrashMethod
	}
	if options.Rand == nil {
		options.Rand = newDefaultRandomProvider()
	}
	crasher := &Crasher{
		CrashPointConfig: make(map[string]float64),
		CrashMethod:      options.CrashMethod,
		Rand:             options.Rand,
		CLIPrefix:        options.CLIPrefix,
		logger:           logging.GetLogger("crash"),
		callerSkip:       options.CallerSkip,
	}
	return crasher
}

// OverrideGlobalOptions overrides global crasher options.
func OverrideGlobalOptions(options CrasherOptions) {
	if options.CrashMethod != nil {
		crashGlobal.CrashMethod = options.CrashMethod
	}
	if options.Rand != nil {
		crashGlobal.Rand = options.Rand
	}
	if options.CLIPrefix != "" {
		crashGlobal.CLIPrefix = options.CLIPrefix
	}
}

// RegisterCrashPoints registers crash points with the global Crasher instance.
func RegisterCrashPoints(crashPointIDs ...string) {
	crashGlobal.RegisterCrashPoints(crashPointIDs...)
}

// RegisterCrashPoints registers crash points for a Crasher instance.
func (c *Crasher) RegisterCrashPoints(crashPointIDs ...string) {
	for _, crashPointID := range crashPointIDs {
		c.CrashPointConfig[crashPointID] = 0.0
	}
}

// ListRegisteredCrashPoints lists the registered crash points for the global
// Crasher instance.
func ListRegisteredCrashPoints() []string {
	return crashGlobal.ListRegisteredCrashPoints()
}

// ListRegisteredCrashPoints lists the registered crash points for a Crasher instance.
func (c *Crasher) ListRegisteredCrashPoints() []string {
	var crashPointIDs []string
	for crashPointID := range c.CrashPointConfig {
		crashPointIDs = append(crashPointIDs, crashPointID)
	}
	return crashPointIDs
}

// Here invokes the global crasher to crash at this point based on the passed in
// crashPointID's probability.
func Here(crashPointID string) {
	crashGlobal.Here(crashPointID)
}

// Here crashes at this point based on the passed in crashPointID's probability.
func (c *Crasher) Here(crashPointID string) {
	_, callerFilename, callerLine, callerInformationIsCorrect := runtime.Caller(c.callerSkip)
	crashPointProbability, ok := c.CrashPointConfig[crashPointID]
	if !ok {
		c.logger.Error("Unknown crash point",
			"crash_point_id", crashPointID,
			"caller_information_is_correct", callerInformationIsCorrect,
			"caller_filename", callerFilename,
			"caller_line", callerLine,
		)
		panic(fmt.Errorf(`Unknown crash point "%s"`, crashPointID))
	}
	// Do nothing if the probability of crashing is set to a value 0 or less.
	if crashPointProbability <= 0 {
		return
	}
	if c.Rand.Float64() <= crashPointProbability {
		c.logger.Info("Crashing intentionally",
			"crash_point_id", crashPointID,
			"crash_point_probability", crashPointProbability,
			"caller_information_is_correct", callerInformationIsCorrect,
			"caller_filename", callerFilename,
			"caller_line", callerLine,
		)
		c.CrashMethod()
	}
}

// Config configure the global crash point values.
func Config(crashPointConfig map[string]float64) {
	crashGlobal.Config(crashPointConfig)
}

// Config configures the crash point probabilities.
func (c *Crasher) Config(crashPointConfig map[string]float64) {
	for crashPointID, crashProbability := range crashPointConfig {
		if _, ok := c.CrashPointConfig[crashPointID]; !ok {
			panic(fmt.Errorf(`Attempted to configure unregistered crash point "%s"`, crashPointID))
		}
		c.CrashPointConfig[crashPointID] = crashProbability
	}
}

// RegisterFlags registers cobra and viper flags for the registered crash
// points.
func RegisterFlags(cmd *cobra.Command) {
	crashGlobal.RegisterFlags(cmd)
}

// RegisterFlags registers CLI flags with cobra and viper used to configure a
// crasher instance.
func (c *Crasher) RegisterFlags(cmd *cobra.Command) {
	for _, crashPointID := range c.ListRegisteredCrashPoints() {
		argFlag := fmt.Sprintf("%s.%s", c.CLIPrefix, crashPointID)
		helpMessage := fmt.Sprintf(`Crash probability of "%s" crash point`, crashPointID)
		if !cmd.Flags().Parsed() {
			cmd.Flags().Float64(argFlag, 0.0, helpMessage)
		}
		_ = viper.BindPFlag(argFlag, cmd.Flags().Lookup(argFlag))
	}
}

// LoadViperArgValues loads viper arg values into the crash point config of the
// global crasher.
func LoadViperArgValues() {
	crashGlobal.LoadViperArgValues()
}

// LoadViperArgValues loads viper arg values into the crash point config.
func (c *Crasher) LoadViperArgValues() {
	for _, crashPointID := range ListRegisteredCrashPoints() {
		argFlag := fmt.Sprintf("%s.%s", c.CLIPrefix, crashPointID)
		c.CrashPointConfig[crashPointID] = viper.GetFloat64(argFlag)
	}
}
