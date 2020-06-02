// Package scenario implements the test scenario abstract interface.
package scenario

import (
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
)

// Scenario is a test scenario identified by name.
type Scenario interface {
	// Clone returns a copy of this scenario instance to be run in parallel.
	Clone() Scenario

	// Name returns the name of the scenario.
	//
	// Note: The name is used when selecting which tests to run, and should
	// be something suitable for use as a command line argument.
	Name() string

	// Parameters returns the settable test parameters.
	Parameters() *env.ParameterFlagSet

	// PreInit performs initial scenario initialization. It is guaranteed to be called before
	// a new fixture is initialized in Fixture.
	PreInit(childEnv *env.Env) error

	// Fixture returns a network fixture to use for this scenario.
	//
	// It may return nil in case the scenario doesn't use a fixture and
	// performs all setup in Init.
	Fixture() (*oasis.NetworkFixture, error)

	// Init initializes the scenario.
	//
	// Network will be provided in case Fixture returned a non-nil value,
	// otherwise it will be nil.
	Init(childEnv *env.Env, net *oasis.Network) error

	// Run runs the scenario.
	Run(childEnv *env.Env) error
}
