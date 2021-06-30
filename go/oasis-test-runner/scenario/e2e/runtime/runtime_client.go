package runtime

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

// TestClient is the interface exposed to implement a runtime test
// client that executes a pre-determined workload against a given runtime.
type TestClient interface {
	Init(*runtimeImpl) error
	Start(context.Context, *env.Env) error
	Wait() error

	// Clone returns a clone of a RuntimeTestClient instance, in a state
	// that is ready for Init.
	Clone() TestClient
}
