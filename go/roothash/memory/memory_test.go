package memory

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	registry "github.com/oasislabs/ekiden/go/registry/memory"
	"github.com/oasislabs/ekiden/go/roothash/tests"
	"github.com/oasislabs/ekiden/go/scheduler/trivial"
	storage "github.com/oasislabs/ekiden/go/storage/memory"
)

func TestRootHashMemory(t *testing.T) {
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
	registry := registry.New(ctx, timeSource)
	cleanupFns = append(cleanupFns, registry.Cleanup)
	scheduler := trivial.New(ctx, timeSource, registry, beacon, nil)
	storagePrivKey, _ := signature.NewPrivateKey(rand.Reader)
	storage := storage.New(timeSource, &storagePrivKey)
	cleanupFns = append(cleanupFns, storage.Cleanup)

	backend := New(ctx, scheduler, registry, nil, 10*time.Second)
	cleanupFns = append(cleanupFns, backend.Cleanup)

	tests.RootHashImplementationTests(t, backend, timeSource, scheduler, storage, registry)
}
