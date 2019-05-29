package trivial

import (
	"context"
	"fmt"
	"sync"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = "trivial"

var (
	_ api.Backend      = (*trivialScheduler)(nil)
	_ api.BlockBackend = (*trivialScheduler)(nil)

	errIncompatibleBackends = fmt.Errorf("scheduler/trivial: incompatible backend(s) for block operations")
)

type trivialScheduler struct {
	sync.Once

	logger *logging.Logger

	service  service.TendermintService
	notifier *pubsub.Broker
}

func (s *trivialScheduler) Cleanup() {
}

func (s *trivialScheduler) GetCommittees(ctx context.Context, id signature.PublicKey) ([]*api.Committee, error) {
	panic("scheduler/trivial: GetCommittees not implemented")
}

func (s *trivialScheduler) WatchCommittees() (<-chan *api.Committee, *pubsub.Subscription) {
	typedCh := make(chan *api.Committee)
	sub := s.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (s *trivialScheduler) GetBlockCommittees(ctx context.Context, id signature.PublicKey, height int64, getBeaconFn api.GetBeaconFunc) ([]*api.Committee, error) { // nolint: gocyclo
	panic("scheduler/trivial: GetBlockCommittees not implemented")
}

func (s *trivialScheduler) worker(ctx context.Context) {
	// TODO %%%
}

// New constracts a new trivial scheduler Backend instance.
func New(ctx context.Context, timeSource epochtime.Backend, registryBackend registry.Backend, beacon beacon.Backend, service service.TendermintService) api.Backend {
	s := &trivialScheduler{
		logger:  logging.GetLogger("scheduler/trivial"),
		service: service,
	}

	go s.worker(ctx)

	return s
}
