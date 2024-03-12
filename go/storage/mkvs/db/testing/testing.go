// Package testing provides helpers for running node database tests.
package testing

import (
	"testing"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

// TestMultipleBackends runs a given test function on the specified node database backends.
func TestMultipleBackends(t *testing.T, backends []api.Factory, fn func(*testing.T, api.Factory)) {
	for _, factory := range backends {
		t.Run(factory.Name(), func(t *testing.T) {
			fn(t, factory)
		})
	}
}
