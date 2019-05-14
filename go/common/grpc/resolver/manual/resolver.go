// Package manual contains a threadsafe method for creating manual grpc resolver
// for context see: https://github.com/oasislabs/ekiden/issues/1622
package manual

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

// Scheme is the name of this resolver.
const Scheme = "ekiden-resolver"

// global is the global resolver registry instance.
var global *registry

// registry is a thread-safe resolver registry.
type registry struct {
	sync.Mutex

	lastID    uint64
	resolvers map[uint64]*manual.Resolver
}

func (r *registry) Scheme() string {
	return Scheme
}

func (r *registry) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOption) (resolver.Resolver, error) {
	// Fetch the actual resolver based on specified target endpoint.
	id, err := strconv.ParseUint(target.Endpoint, 10, 64)
	if err != nil {
		return nil, errors.New("resolver: non-numeric id used as endpoint")
	}

	resolver, err := r.lookup(id)
	if err != nil {
		return nil, err
	}

	return resolver.Build(target, cc, opts)
}

func (r *registry) lookup(id uint64) (*manual.Resolver, error) {
	r.Lock()
	defer r.Unlock()

	resolver := r.resolvers[id]
	if resolver == nil {
		return nil, errors.New("resolver: not found")
	}

	return resolver, nil
}

func (r *registry) generate() (*manual.Resolver, string, func()) {
	r.Lock()
	defer r.Unlock()

	// NOTE: Scheme can be duplicated as the resolver is never registered.
	resolver := manual.NewBuilderWithScheme(Scheme)
	id := r.lastID
	r.lastID++
	r.resolvers[id] = resolver
	endpoint := fmt.Sprintf("%s:///%d", Scheme, id)

	return resolver, endpoint, func() { r.cleanup(id) }
}

func (r *registry) cleanup(id uint64) {
	r.Lock()
	defer r.Unlock()

	delete(r.resolvers, id)
}

// NewManualResolver creates a new manual resolver that can be used without
// running into concurrency issues as the original manual.Resolver is not
// thread-safe due to the resolver registry not being thread-safe.
//
// This function returns the resolver, the URI that should be used in Dial
// and a cleanup function that should be called when the resolver is no longer
// needed.
func NewManualResolver() (*manual.Resolver, string, func()) {
	return global.generate()
}

func init() {
	global = &registry{
		resolvers: make(map[uint64]*manual.Resolver),
	}

	resolver.Register(global)
}
