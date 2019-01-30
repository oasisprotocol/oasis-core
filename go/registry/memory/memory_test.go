package memory

import (
	"context"
	"testing"

	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/registry/tests"
)

func TestRegistryMemory(t *testing.T) {
	ctx := context.Background()

	timeSource := mock.New()
	backend := New(ctx, timeSource)
	defer backend.Cleanup()

	tests.RegistryImplementationTests(t, backend, timeSource)
}
