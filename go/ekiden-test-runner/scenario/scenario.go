// Package scenario implements the test scenario abstract interface.
package scenario

import "github.com/oasislabs/ekiden/go/ekiden-test-runner/env"

// Scenario is a test scenario identified by name.
type Scenario interface {
	// Name returns the name of the scenario.
	//
	// Note: The name is used when selecting which tests to run, and should
	// be something suitable for use as a command line argument.
	Name() string

	// Init initializes the scenario.
	Init(childEnv *env.Env) error

	// Run runs the scenario.
	Run(childEnv *env.Env) error
}
