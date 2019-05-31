package trivial

import (
	"context"
	"testing"

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
	registry := memory.New(ctx, timeSource)
	cleanupFns = append(cleanupFns, registry.Cleanup)

	backend, err := New(ctx, nil)
	if err != nil {
		t.Fatalf("couldn't create backend: %s", err.Error())
	}
	cleanupFns = append(cleanupFns, backend.Cleanup)

	tests.SchedulerImplementationTests(t, backend, timeSource, registry)
}
