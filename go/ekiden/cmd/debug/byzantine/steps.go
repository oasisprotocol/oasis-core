package byzantine

import (
	"context"
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
)

var _ api.Backend = (*fakeTimeBackend)(nil)

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

func (ht *honestTendermint) start(dataDir string) error {
	if ht.service != nil {
		return errors.New("honest Tendermint service already started")
	}

	signerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerEntity)
	identity, err := identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		return errors.Wrap(err, "identity LoadOrGenerate")
	}
	genesis, err := genesis.New(identity)
	if err != nil {
		return errors.Wrap(err, "genesis New")
	}
	ht.service = tendermint.New(context.Background(), dataDir, identity, genesis)

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
