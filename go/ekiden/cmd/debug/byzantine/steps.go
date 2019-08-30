package byzantine

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/genesis"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint"
	beaconapp "github.com/oasislabs/ekiden/go/tendermint/apps/beacon"
	keymanagerapp "github.com/oasislabs/ekiden/go/tendermint/apps/keymanager"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
	roothashapp "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	schedulerapp "github.com/oasislabs/ekiden/go/tendermint/apps/scheduler"
	stakingapp "github.com/oasislabs/ekiden/go/tendermint/apps/staking"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

const (
	defaultRuntimeIDHex = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	defaultRuntimeID signature.PublicKey

	_ api.Backend = (*fakeTimeBackend)(nil)
	_ p2p.Handler = (*p2pRecvHandler)(nil)
)

func initDefaultIdentity(dataDir string) (*identity.Identity, error) {
	signerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerEntity)
	id, err := identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		return nil, errors.Wrap(err, "identity LoadOrGenerate")
	}
	return id, nil
}

// fakeTimeBackend is like TendermintBackend (of epochtime), but without
// any workers.
type fakeTimeBackend struct{}

// GetEpoch implements epochtime Backend.
func (*fakeTimeBackend) GetEpoch(ctx context.Context, height int64) (api.EpochTime, error) {
	if height == 0 {
		panic("0 height not supported")
	}
	return api.EpochTime(height / 30), nil
}

// GetEpochBlock implements epochtime Backend.
func (*fakeTimeBackend) GetEpochBlock(ctx context.Context, epoch api.EpochTime) (int64, error) {
	panic("GetEpochBlock not supported")
}

// WatchEpochs implements epochtime Backend.
func (*fakeTimeBackend) WatchEpochs() (<-chan api.EpochTime, *pubsub.Subscription) {
	panic("WatchEpochs not supported")
}

type honestTendermint struct {
	service service.TendermintService
}

func newHonestTendermint() *honestTendermint {
	return &honestTendermint{}
}

func (ht *honestTendermint) start(id *identity.Identity, dataDir string) error {
	if ht.service != nil {
		return errors.New("honest Tendermint service already started")
	}

	genesis, err := genesis.New()
	if err != nil {
		return errors.Wrap(err, "genesis New")
	}
	ht.service = tendermint.New(context.Background(), dataDir, id, genesis)

	if err := ht.service.ForceInitialize(); err != nil {
		return errors.Wrap(err, "honest Tendermint service ForceInitialize")
	}

	// Register honest mux apps.
	// This isn't very flexible. It's configured to match what we use in end-to-end tests.
	// And we do that mostly by hardcoding options. We could make this more flexible with command
	// line flags in future work.
	timeSource := &fakeTimeBackend{}
	// Tendermint epochtime has no registration
	if err := ht.service.RegisterApplication(beaconapp.New(timeSource, &beacon.Config{
		DebugDeterministic: true,
	})); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication beacon")
	}
	if err := ht.service.RegisterApplication(stakingapp.New(nil)); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication staking")
	}
	if err := ht.service.RegisterApplication(registryapp.New(timeSource, &registry.Config{
		DebugAllowRuntimeRegistration: false,
		DebugBypassStake:              false,
	})); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication registry")
	}
	if err := ht.service.RegisterApplication(keymanagerapp.New(timeSource)); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication keymanager")
	}
	if err := ht.service.RegisterApplication(schedulerapp.New(timeSource, &scheduler.Config{
		DebugBypassStake: false,
	})); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication scheduler")
	}
	// storage has no registration
	if err := ht.service.RegisterApplication(roothashapp.New(context.Background(), timeSource, nil, 10*time.Second)); err != nil {
		return errors.Wrap(err, "honest Tendermint service RegisterApplication roothash")
	}

	if err := ht.service.Start(); err != nil {
		return errors.Wrap(err, "honest Tendermint service Start")
	}
	logger.Debug("honest Tendermint service waiting for Tendermint start")
	<-ht.service.Started()
	logger.Debug("honest Tendermint service waiting for Tendermint sync")
	<-ht.service.Synced()
	logger.Debug("honest Tendermint service sync done")

	return nil
}

func (ht honestTendermint) stop() error {
	if ht.service == nil {
		return errors.New("honest Tendermint service not started")
	}

	ht.service.Stop()
	logger.Debug("honest Tendermint service waiting for quit")
	<-ht.service.Quit()
	logger.Debug("honest Tendermint service quit done")
	ht.service = nil

	return nil
}

type p2pReqRes struct {
	peerID     signature.PublicKey
	msg        *p2p.Message
	responseCh chan<- error
}

type p2pHandle struct {
	context  context.Context
	cancel   context.CancelFunc
	service  *p2p.P2P
	requests chan p2pReqRes
}

func newP2PHandle() *p2pHandle {
	return &p2pHandle{
		requests: make(chan p2pReqRes),
	}
}

// p2pRecvHandler forwards requests to, and responses from, a goroutine.
type p2pRecvHandler struct {
	target *p2pHandle
}

// IsPeerAuthorized implements p2p Handler.
func (h *p2pRecvHandler) IsPeerAuthorized(peerID signature.PublicKey) bool {
	// The Byzantine node itself isn't especially robust. We assume that
	// the other nodes are honest.
	return true
}

// HandlePeerMessage implements p2p Handler.
func (h *p2pRecvHandler) HandlePeerMessage(peerID signature.PublicKey, msg *p2p.Message) error {
	responseCh := make(chan error)
	h.target.requests <- p2pReqRes{
		peerID:     peerID,
		msg:        msg,
		responseCh: responseCh,
	}
	return <-responseCh
}

func (ph *p2pHandle) start(id *identity.Identity, runtimeID signature.PublicKey) error {
	if ph.service != nil {
		return errors.New("P2P service already started")
	}

	ph.context, ph.cancel = context.WithCancel(context.Background())
	var err error
	ph.service, err = p2p.New(ph.context, id)
	if err != nil {
		return errors.Wrap(err, "P2P service New")
	}

	ph.service.RegisterHandler(runtimeID, &p2pRecvHandler{
		target: ph,
	})

	return nil
}

func (ph *p2pHandle) stop() error {
	if ph.service == nil {
		return errors.New("P2P service not started")
	}

	ph.cancel()
	ph.service = nil
	ph.context = nil
	ph.cancel = nil

	return nil
}

func init() {
	if err := defaultRuntimeID.UnmarshalHex(defaultRuntimeIDHex); err != nil {
		panic(fmt.Sprintf("default runtime ID UnmarshalHex: %+v", err))
	}
}
