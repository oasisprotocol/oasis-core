package memory

import (
	"testing"
	"time"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	registry "github.com/oasislabs/ekiden/go/registry/memory"
	"github.com/oasislabs/ekiden/go/roothash/tests"
	"github.com/oasislabs/ekiden/go/scheduler/trivial"
	storage "github.com/oasislabs/ekiden/go/storage/memory"
)

func TestRootHashMemory(t *testing.T) {
	timeSource := mock.New()
	beacon := insecure.New(timeSource)
	registry := registry.New(timeSource)
	defer registry.Cleanup()
	scheduler := trivial.New(timeSource, registry, beacon, nil)
	storage := storage.New(timeSource)
	defer storage.Cleanup()

	backend := New(scheduler, storage, registry, nil, 10*time.Second)

	tests.RootHashImplementationTests(t, backend, timeSource, scheduler, storage, registry)
}
