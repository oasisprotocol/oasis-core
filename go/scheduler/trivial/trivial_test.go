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
	ctx, cancelFn := context.WithCancel(context.Background())
	var cleanupFns []func()
	defer func() {
		cancelFn()
		for _, fn := range cleanupFns {
			fn()
		}
	}()

	timeSource := mock.New()
	beacon := insecure.New(ctx, timeSource)
	registry := memory.New(ctx, timeSource)
	cleanupFns = append(cleanupFns, registry.Cleanup)

	backend := New(ctx, timeSource, registry, beacon, nil)
	cleanupFns = append(cleanupFns, backend.Cleanup)

	tests.SchedulerImplementationTests(t, backend, timeSource, registry)
}
