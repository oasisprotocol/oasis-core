package memory

import (
	"context"
	"testing"

	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/registry/tests"
)

func TestRegistryMemory(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())

	timeSource := mock.New()
	backend := New(ctx, timeSource)
	defer func() {
		cancelFn()
		backend.Cleanup()
	}()

	tests.RegistryImplementationTests(t, backend, timeSource)
}
