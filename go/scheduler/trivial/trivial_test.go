package trivial

import (
	"testing"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/registry/memory"
	"github.com/oasislabs/ekiden/go/scheduler/tests"
)

func TestSchedulerTrivial(t *testing.T) {
	timeSource := mock.New()
	beacon := insecure.New(timeSource)
	registry := memory.New(timeSource)
	defer registry.Cleanup()

	backend := New(timeSource, registry, beacon, nil)

	tests.SchedulerImplementationTests(t, backend, timeSource, registry)
}
