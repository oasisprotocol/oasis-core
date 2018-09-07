package trivial

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/scheduler/api"
)

// BackendName is the name of this implementation.
const BackendName = "trivial"

var (
	_ api.Backend      = (*trivialScheduler)(nil)
	_ api.BlockBackend = (*trivialScheduler)(nil)

	rngContextCompute = []byte("EkS-Dummy-Compute")
	rngContextStorage = []byte("EkS-Dummy-Storage")

	errIncompatibleBackends = fmt.Errorf("scheduler/trivial: incompatible backend(s) for block operations")
)

type trivialScheduler struct {
	logger *logging.Logger

	timeSource epochtime.Backend
	beacon     beacon.Backend
	registry   registry.Backend

	state *trivialSchedulerState

	notifier *pubsub.Broker
}

type trivialSchedulerState struct {
	sync.RWMutex

	nodeLists  map[epochtime.EpochTime][]*node.Node
	beacons    map[epochtime.EpochTime][]byte
	contracts  map[signature.MapKey]*contract.Contract
	committees map[epochtime.EpochTime]map[signature.MapKey][]*api.Committee

	epoch     epochtime.EpochTime
	lastElect epochtime.EpochTime
}

func (s *trivialSchedulerState) canElect() bool {
	return s.nodeLists[s.epoch] != nil && s.beacons[s.epoch] != nil
}

func (s *trivialSchedulerState) elect(con *contract.Contract, epoch epochtime.EpochTime, notifier *pubsub.Broker) ([]*api.Committee, error) { //nolint:gocyclo
	var committees []*api.Committee

	maybeBroadcast := func() {
		if notifier != nil {
			for _, committee := range committees {
				notifier.Broadcast(committee)
			}
		}
	}

	// Initialize the map for this epoch iff it is missing.
	if s.committees[epoch] == nil {
		s.committees[epoch] = make(map[signature.MapKey][]*api.Committee)
	}
	comMap := s.committees[epoch]

	// This may be cached due to an external entity polling for this.
	conID := con.ID.ToMapKey()
	if committees = comMap[conID]; committees != nil {
		maybeBroadcast()
		return committees, nil
	}

	nodeList := s.nodeLists[epoch]
	beacon := s.beacons[epoch]
	nrNodes := len(nodeList)

	for _, kind := range []api.CommitteeKind{api.Compute, api.Storage} {
		var sz int
		var ctx []byte
		switch kind {
		case api.Compute:
			sz = int(con.ReplicaGroupSize + con.ReplicaGroupBackupSize)
			ctx = rngContextCompute
		case api.Storage:
			sz = int(con.StorageGroupSize)
			ctx = rngContextStorage
		default:
			return nil, fmt.Errorf("scheduler: invalid committee type: %v", kind)
		}

		if sz == 0 {
			return nil, fmt.Errorf("scheduler: empty committee not allowed")
		}
		if sz > nrNodes {
			return nil, fmt.Errorf("scheduler: committee size exceeds available nodes")
		}

		drbg, err := drbg.New(crypto.SHA512, beacon, con.ID[:], ctx)
		if err != nil {
			return nil, err
		}
		rngSrc := mathrand.New(drbg)
		rng := rand.New(rngSrc)
		idxs := rng.Perm(nrNodes)

		committee := &api.Committee{
			Kind:     kind,
			Contract: con,
			ValidFor: epoch,
		}

		for i := 0; i < sz; i++ {
			var role api.Role
			switch {
			case i == 0:
				role = api.Leader
			case i >= int(con.ReplicaGroupSize):
				role = api.BackupWorker
			default:
				role = api.Worker
			}
			committee.Members = append(committee.Members, &api.CommitteeNode{
				Role:      role,
				PublicKey: nodeList[idxs[i]].ID,
			})
		}

		committees = append(committees, committee)
	}

	comMap[conID] = committees
	maybeBroadcast()

	return committees, nil
}

func (s *trivialSchedulerState) prune() {
	pruneBefore := s.epoch - 1
	if pruneBefore > s.epoch {
		return
	}

	for epoch := range s.nodeLists {
		if epoch < pruneBefore {
			delete(s.nodeLists, epoch)
		}
	}
	for epoch := range s.beacons {
		if epoch < pruneBefore {
			delete(s.beacons, epoch)
		}
	}

	s.Lock()
	defer s.Unlock()

	for epoch := range s.committees {
		if epoch < pruneBefore {
			delete(s.committees, epoch)
		}
	}
}

func (s *trivialSchedulerState) updateEpoch(epoch epochtime.EpochTime) {
	s.Lock()
	defer s.Unlock()

	s.epoch = epoch
}

func (s *trivialScheduler) GetCommittees(ctx context.Context, id signature.PublicKey) ([]*api.Committee, error) {
	s.state.RLock()
	defer s.state.RUnlock()

	comMap := s.state.committees[s.state.epoch]
	if comMap == nil {
		return nil, nil
	}
	return comMap[id.ToMapKey()], nil
}

func (s *trivialScheduler) WatchCommittees() (<-chan *api.Committee, *pubsub.Subscription) {
	typedCh := make(chan *api.Committee)
	sub := s.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

func (s *trivialScheduler) GetBlockCommittees(ctx context.Context, id signature.PublicKey, height int64) ([]*api.Committee, error) { // nolint: gocyclo
	timeSource, ok := s.timeSource.(epochtime.BlockBackend)
	if !ok {
		return nil, errIncompatibleBackends
	}
	beacon, ok := s.beacon.(beacon.BlockBackend)
	if !ok {
		return nil, errIncompatibleBackends
	}
	reg, ok := s.registry.(registry.BlockBackend)
	if !ok {
		return nil, errIncompatibleBackends
	}

	epoch, _, err := timeSource.GetBlockEpoch(ctx, height)
	if err != nil {
		return nil, err
	}

	conID := id.ToMapKey()

	s.state.Lock()
	defer s.state.Unlock()

	// Service the request from the cache if possible.
	if comMap := s.state.committees[epoch]; comMap != nil {
		if committees := comMap[conID]; committees != nil {
			return committees, nil
		}
	}

	// Do the election for the contract now.  Since rescheduling isn't
	// allowed, this will give identical output to what the worker will
	// do eventually.
	//
	// Note: Since we're likely racing ahead of the worker, we need to
	// poll the other backends for what we need to elect.

	if b := s.state.beacons[epoch]; b == nil {
		b, err = beacon.GetBlockBeacon(ctx, height)
		if err != nil {
			return nil, err
		}
		s.state.beacons[epoch] = b
	}

	if nodeList := s.state.nodeLists[epoch]; nodeList == nil {
		var nl *registry.NodeList
		nl, err = reg.GetBlockNodeList(ctx, height)
		if err != nil {
			return nil, err
		}
		s.state.nodeLists[epoch] = nl.Nodes
	}

	con, err := reg.GetContract(ctx, id)
	if err != nil {
		return nil, err
	}

	return s.state.elect(con, epoch, nil)
}

func (s *trivialScheduler) electSingle(con *contract.Contract, notifier *pubsub.Broker) {
	s.state.Lock()
	defer s.state.Unlock()

	committees, err := s.state.elect(con, s.state.epoch, s.notifier)
	if err != nil {
		s.logger.Debug("worker: failed to elect (single)",
			"contract", con,
			"err", err,
		)
		return
	}

	s.logger.Debug("worker: election (single)",
		"contract", con,
		"committees", committees,
	)
}

func (s *trivialScheduler) electAll(notifier *pubsub.Broker) {
	s.state.Lock()
	defer s.state.Unlock()

	for _, v := range s.state.contracts {
		committees, err := s.state.elect(v, s.state.epoch, s.notifier)
		if err != nil {
			s.logger.Debug("worker: failed to elect",
				"contract", v,
				"err", err,
			)
			continue
		}

		s.logger.Debug("worker: election",
			"contract", v,
			"committees", committees,
		)
	}

	s.state.lastElect = s.state.epoch
}

func (s *trivialScheduler) worker() { //nolint:gocyclo
	timeCh, sub := s.timeSource.WatchEpochs()
	defer sub.Close()

	contractCh, sub := s.registry.WatchContracts()
	defer sub.Close()

	nodeListCh, sub := s.registry.WatchNodeList()
	defer sub.Close()

	beaconCh, sub := s.beacon.WatchBeacons()
	defer sub.Close()

	for {
		select {
		case epoch := <-timeCh:
			if epoch == s.state.epoch {
				continue
			}
			s.logger.Debug("worker: epoch transition",
				"prev_epoch", s.state.epoch,
				"epoch", epoch,
			)
			s.state.updateEpoch(epoch)
			s.state.prune()
		case ev := <-nodeListCh:
			// TODO: Check to see if there is an existing *different*
			// node list, and ignore the new one.
			//
			// Omitting the check is mostly harmess, since a changing
			// node list within an epoch is an invariant violation.
			s.logger.Debug("worker: node list for epoch",
				"epoch", ev.Epoch,
			)
			s.state.nodeLists[ev.Epoch] = ev.Nodes
		case ev := <-beaconCh:
			if b := s.state.beacons[ev.Epoch]; b != nil {
				if !bytes.Equal(b, ev.Beacon) {
					s.logger.Error("worker: beacon when already received",
						"epoch", ev.Epoch,
						"beacon", hex.EncodeToString(b),
						"new_beacon", hex.EncodeToString(ev.Beacon),
					)
					continue
				}
			}
			s.logger.Debug("worker: beacon for epoch",
				"epoch", ev.Epoch,
				"beacon", hex.EncodeToString(ev.Beacon),
			)
			s.state.beacons[ev.Epoch] = ev.Beacon
		case contract := <-contractCh:
			mk := contract.ID.ToMapKey()
			if con := s.state.contracts[mk]; con != nil {
				s.logger.Error("worker: contract registration ID conflict",
					"contract", con,
					"new_contract", contract,
				)
				continue
			}
			s.state.contracts[mk] = contract
			if s.state.epoch == s.state.lastElect && s.state.canElect() {
				// Attempt to elect the committee if possible, since
				// the election for the epoch happened already.
				s.electSingle(contract, s.notifier)
			}
			continue
		}

		if s.state.epoch == s.state.lastElect || !s.state.canElect() {
			continue
		}

		// Elect ALL THE THINGS. \o/
		s.logger.Debug("worker: electing for epoch",
			"epoch", s.state.epoch,
		)

		s.electAll(s.notifier)
	}
}

// New constracts a new trivial scheduler Backend instance.
func New(timeSource epochtime.Backend, registry registry.Backend, beacon beacon.Backend) api.Backend {
	s := &trivialScheduler{
		logger:     logging.GetLogger("scheduler/trivial"),
		timeSource: timeSource,
		registry:   registry,
		beacon:     beacon,
		state: &trivialSchedulerState{
			nodeLists:  make(map[epochtime.EpochTime][]*node.Node),
			beacons:    make(map[epochtime.EpochTime][]byte),
			contracts:  make(map[signature.MapKey]*contract.Contract),
			committees: make(map[epochtime.EpochTime]map[signature.MapKey][]*api.Committee),
			epoch:      epochtime.EpochInvalid,
			lastElect:  epochtime.EpochInvalid,
		},
	}
	s.notifier = pubsub.NewBrokerEx(func(ch *channels.InfiniteChannel) {
		s.state.RLock()
		defer s.state.RUnlock()

		if s.state.lastElect != s.state.epoch {
			// A mass-election will happen Real Soon Now, don't bother.
			s.logger.Debug("notifier: not sending stale committees",
				"last_elect", s.state.lastElect,
				"epoch", s.state.epoch,
			)
			return
		}

		comMap := s.state.committees[s.state.epoch]
		if comMap == nil {
			s.logger.Debug("notifier: no committees for epoch",
				"epoch", s.state.epoch,
			)
			return
		}

		for _, v := range comMap {
			for _, vv := range v {
				ch.In() <- vv
			}
		}
	})

	go s.worker()

	return s
}
