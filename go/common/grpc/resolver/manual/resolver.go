// Package manual contains a threadsafe method for creating manual grpc resolver
// for context see: https://github.com/oasislabs/ekiden/issues/1622
// Note: this is thread-safe under assumption that every registration of manual resolver
// uses this object.
package manual

import (
	"sync"

	"google.golang.org/grpc/resolver/manual"
)

type resolverState struct {
	grpcResolverLock sync.Mutex
}

var state *resolverState
var once sync.Once

// ThreadSafeGenerateAndRegisterManualResolver creates a new gRPC manual.Resolver in a threadsafe manner
func ThreadSafeGenerateAndRegisterManualResolver() (*manual.Resolver, func()) {
	// The gRPC manual resolver is supposed to allow for per-invocation resolver
	// instances, by generating resolvers for randomized schemes, presumably at
	// runtime.
	//
	// It has been said that there are primitives that can be used to protect
	// shared datastructures from concurrent writes.

	once.Do(func() {
		state = &resolverState{}
	})

	state.grpcResolverLock.Lock()
	defer state.grpcResolverLock.Unlock()

	return manual.GenerateAndRegisterManualResolver()
}
