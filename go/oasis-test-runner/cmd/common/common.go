// Package common contains common constants and variables.
package common

import (
	"fmt"
	"sort"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	CfgLogFmt   = "log.format"
	CfgLogLevel = "log.level"
	CfgTest     = "test"
	CfgTestP    = "t"

	// ScenarioParamsMask is the form of parameters passed to specific scenario.
	//
	// [1] parameter is test name, [2] parameter is parameter name. This is
	// used when binding and parsing (recursive) parameters with viper.
	ScenarioParamsMask = "%[1]s.%[2]s"
)

var (
	scenarios        = make(map[string]scenario.Scenario)
	defaultScenarios []scenario.Scenario
)

// GetScenarios returns all registered scenarios.
//
// This function *is not* thread-safe.
func GetScenarios() map[string]scenario.Scenario {
	return scenarios
}

// GetScenarioNames returns the names of all scenarios.
func GetScenarioNames() (names []string) {
	for name := range scenarios {
		names = append(names, name)
	}
	sort.Strings(names)
	return
}

// GetDefaultScenarios returns all registered default scenarios.
//
// This function *is not* thread-safe.
func GetDefaultScenarios() []scenario.Scenario {
	return defaultScenarios
}

// RegisterScenario adds given scenario to the map of all scenarios and optionally appends it to default scenarios list.
//
// This function *is not* thread-safe.
func RegisterScenario(s scenario.Scenario, d bool) error {
	n := strings.ToLower(s.Name())
	if _, ok := scenarios[n]; ok {
		return fmt.Errorf("RegisterScenario: scenario already registered: %s", n)
	}

	scenarios[n] = s

	if d {
		defaultScenarios = append(defaultScenarios, s)
	}

	return nil
}
