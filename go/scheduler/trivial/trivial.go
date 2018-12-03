package trivial

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
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

	rngContextCompute = []byte("EkS-Dummy-Compute")
	rngContextStorage = []byte("EkS-Dummy-Storage")

	errIncompatibleBackends = fmt.Errorf("scheduler/trivial: incompatible backend(s) for block operations")
)

type trivialScheduler struct {
	sync.Once

	logger *logging.Logger

	timeSource epochtime.Backend
	beacon     beacon.Backend
	registry   registry.Backend

	state *trivialSchedulerState

	service  service.TendermintService
	notifier *pubsub.Broker

	closeCh  chan struct{}
	closedCh chan struct{}
}

type trivialSchedulerState struct {
	sync.RWMutex

	logger *logging.Logger

	nodeLists  map[epochtime.EpochTime]map[node.TEEHardware][]*node.Node
	beacons    map[epochtime.EpochTime][]byte
	runtimes   map[signature.MapKey]*registry.Runtime
	committees map[epochtime.EpochTime]map[signature.MapKey][]*api.Committee

	epoch     epochtime.EpochTime
	lastElect epochtime.EpochTime
}

func (s *trivialSchedulerState) canElect() bool {
	return s.nodeLists[s.epoch] != nil && s.beacons[s.epoch] != nil
}

func (s *trivialSchedulerState) elect(con *registry.Runtime, epoch epochtime.EpochTime, notifier *pubsub.Broker) ([]*api.Committee, error) { //nolint:gocyclo
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

	var hw node.TEEHardware
	if con.FeaturesSGX {
		hw = node.TEEHardwareIntelSGX
	}

	nodeList := s.nodeLists[epoch][hw]
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
			Kind:      kind,
			RuntimeID: con.ID,
			ValidFor:  epoch,
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

func (s *trivialSchedulerState) updateNodeListLocked(epoch epochtime.EpochTime, nodes []*node.Node, ts time.Time) {
	// Invariant: s.Lock() held already.

	// Re-scheduling is not allowed, and if there are node lists already there
	// is nothing to do.
	if s.nodeLists[epoch] != nil {
		return
	}

	m := make(map[node.TEEHardware][]*node.Node)
	s.nodeLists[epoch] = m

	// Special case: No TEE support is requested by the runtime.
	m[node.TEEHardwareInvalid] = nodes

	// Build the per-TEE implementation node lists for the given epoch.
	// It is safe to do it this way as `nodes` is already sorted in
	// the appropriate order.
	for _, node := range nodes {
		caps := node.Capabilities.TEE
		if caps == nil { // No TEE support at all.
			continue
		}

		if err := caps.Verify(ts); err != nil {
			s.logger.Warn("failed to verify node TEE attestation",
				"err", err,
				"node", node,
				"time_stamp", ts,
			)
			continue
		}

		hw := caps.Hardware
		m[hw] = append(m[hw], node)
	}
}

func (s *trivialScheduler) Cleanup() {
	s.Do(func() {
		close(s.closeCh)
		<-s.closedCh
	})
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

	// Do the election for the runtime now.  Since rescheduling isn't
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
		var ts time.Time
		ts, err = s.getEpochTransitionTime(epoch)
		if err != nil {
			return nil, err
		}
		s.state.updateNodeListLocked(epoch, nl.Nodes, ts)
	}

	con, err := reg.GetRuntime(ctx, id)
	if err != nil {
		return nil, err
	}

	return s.state.elect(con, epoch, nil)
}

func (s *trivialScheduler) electSingle(con *registry.Runtime, notifier *pubsub.Broker) {
	s.state.Lock()
	defer s.state.Unlock()

	committees, err := s.state.elect(con, s.state.epoch, s.notifier)
	if err != nil {
		s.logger.Debug("worker: failed to elect (single)",
			"runtime", con,
			"err", err,
		)
		return
	}

	s.logger.Debug("worker: election (single)",
		"runtime", con,
		"committees", committees,
	)
}

func (s *trivialScheduler) electAll(notifier *pubsub.Broker) {
	s.state.Lock()
	defer s.state.Unlock()

	for _, v := range s.state.runtimes {
		committees, err := s.state.elect(v, s.state.epoch, s.notifier)
		if err != nil {
			s.logger.Debug("worker: failed to elect",
				"runtime", v,
				"err", err,
			)
			continue
		}

		s.logger.Debug("worker: election",
			"runtime", v,
			"committees", committees,
		)
	}

	s.state.lastElect = s.state.epoch
}

func (s *trivialScheduler) worker() { //nolint:gocyclo
	defer close(s.closedCh)

	timeCh, sub := s.timeSource.WatchEpochs()
	defer sub.Close()

	runtimeCh, sub := s.registry.WatchRuntimes()
	defer sub.Close()

	nodeListCh, sub := s.registry.WatchNodeList()
	defer sub.Close()

	beaconCh, sub := s.beacon.WatchBeacons()
	defer sub.Close()

	for {
		select {
		case <-s.closeCh:
			return
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
			ts, err := s.getEpochTransitionTime(ev.Epoch)
			if err != nil {
				// Attestation validations will fail till after the epoch transition.
				s.logger.Error("worker: failed to get epoch transition time",
					"err", err,
				)
			}

			s.logger.Debug("worker: node list for epoch",
				"epoch", ev.Epoch,
				"transition_at", ts,
			)

			s.state.Lock()
			s.state.updateNodeListLocked(ev.Epoch, ev.Nodes, ts)
			s.state.Unlock()
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
		case runtime := <-runtimeCh:
			mk := runtime.ID.ToMapKey()
			if con := s.state.runtimes[mk]; con != nil {
				s.logger.Error("worker: runtime registration ID conflict",
					"runtime", con,
					"new_runtime", runtime,
				)
				continue
			}
			s.state.runtimes[mk] = runtime
			if s.state.epoch == s.state.lastElect && s.state.canElect() {
				// Attempt to elect the committee if possible, since
				// the election for the epoch happened already.
				s.electSingle(runtime, s.notifier)
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

func (s *trivialScheduler) getEpochTransitionTime(epoch epochtime.EpochTime) (time.Time, error) {
	timeSource, ok := s.timeSource.(epochtime.BlockBackend)
	if !ok || s.service == nil {
		// Incompatible time backend, no BFT time available.  This
		// WILL cause inconsitencies if the attestations happen to
		// expire at inconvenient times.
		//
		// This isn't treated as an error under the assumption that
		// if the user configures a non-BFT time source, they are
		// presumably ok with the consequences of their decision.
		//
		// All production deployments will never hit this code path.
		return time.Now(), nil
	}

	blockHeight, err := timeSource.GetEpochBlock(context.Background(), epoch)
	if err != nil {
		return time.Time{}, err
	}

	switch blockHeight {
	case 0:
		// No timestamp in the genesis state.
		return time.Time{}, fmt.Errorf("scheduler/trivial: no epoch transition time for 0th epoch")
	default:
		block, err := s.service.GetBlock(blockHeight)
		if err != nil {
			return time.Time{}, err
		}

		return block.Header.Time, nil
	}
}

// New constracts a new trivial scheduler Backend instance.
func New(timeSource epochtime.Backend, registryBackend registry.Backend, beacon beacon.Backend, service service.TendermintService) api.Backend {
	s := &trivialScheduler{
		logger:     logging.GetLogger("scheduler/trivial"),
		timeSource: timeSource,
		registry:   registryBackend,
		beacon:     beacon,
		state: &trivialSchedulerState{
			nodeLists:  make(map[epochtime.EpochTime]map[node.TEEHardware][]*node.Node),
			beacons:    make(map[epochtime.EpochTime][]byte),
			runtimes:   make(map[signature.MapKey]*registry.Runtime),
			committees: make(map[epochtime.EpochTime]map[signature.MapKey][]*api.Committee),
			epoch:      epochtime.EpochInvalid,
			lastElect:  epochtime.EpochInvalid,
		},
		service:  service,
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}
	s.state.logger = s.logger
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
