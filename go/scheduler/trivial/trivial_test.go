package trivial

import (
	"context"
	"testing"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/registry/memory"
	"github.com/oasislabs/ekiden/go/scheduler/tests"
)

func TestSchedulerTrivial(t *testing.T) {
	ctx := context.Background()

	timeSource := mock.New()
	beacon := insecure.New(ctx, timeSource)
	registry := memory.New(ctx, timeSource)
	defer registry.Cleanup()

	backend := New(ctx, timeSource, registry, beacon, nil)

	tests.SchedulerImplementationTests(t, backend, timeSource, registry)
}
