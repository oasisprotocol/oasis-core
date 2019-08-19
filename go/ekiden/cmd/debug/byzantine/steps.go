package byzantine

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/genesis"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	beaconapp "github.com/oasislabs/ekiden/go/tendermint/apps/beacon"
	keymanagerapp "github.com/oasislabs/ekiden/go/tendermint/apps/keymanager"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
	roothashapp "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	schedulerapp "github.com/oasislabs/ekiden/go/tendermint/apps/scheduler"
	stakingapp "github.com/oasislabs/ekiden/go/tendermint/apps/staking"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
	"github.com/oasislabs/ekiden/go/worker/registration"
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

func registryRegisterNode(svc service.TendermintService, id *identity.Identity, dataDir string, committeeAddresses []node.Address, p2pInfo node.P2PInfo, runtimeID signature.PublicKey, roles node.RolesMask) error { // nolint: deadcode, unused
	entityID, registrationSigner, err := registration.GetRegistrationSigner(logging.GetLogger("cmd/byzantine/registration"), dataDir, id)
	if err != nil {
		return errors.Wrap(err, "registration GetRegistrationSigner")
	}
	if registrationSigner == nil {
		return errors.New("nil registrationSigner")
	}

	nodeDesc := &node.Node{
		ID:         id.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: 1000,
		Committee: node.CommitteeInfo{
			Certificate: id.TLSCertificate.Certificate[0],
			Addresses:   committeeAddresses,
		},
		P2P:              p2pInfo,
		RegistrationTime: uint64(time.Now().Unix()),
		Runtimes: []*node.Runtime{
			&node.Runtime{
				ID: runtimeID,
			},
		},
		Roles: roles,
	}
	signedNode, err := node.SignNode(registrationSigner, registry.RegisterGenesisNodeSignatureContext, nodeDesc)
	if err != nil {
		return errors.Wrap(err, "node SignNode")
	}

	if err := svc.BroadcastTx(registryapp.TransactionTag, registryapp.Tx{
		TxRegisterNode: &registryapp.TxRegisterNode{
			Node: *signedNode,
		},
	}); err != nil {
		return errors.Wrap(err, "Tendermint BroadcastTx")
	}

	return nil
}

func registryGetNode(svc service.TendermintService, height int64, id signature.PublicKey) (*node.Node, error) { // nolint: deadcode, unused
	response, err := svc.Query(registryapp.QueryGetNode, tmapi.QueryGetByIDRequest{
		ID: id,
	}, height)
	if err != nil {
		return nil, errors.Wrapf(err, "Tendermint Query %s", registryapp.QueryGetNodes)
	}

	var node node.Node
	if err := cbor.Unmarshal(response, &node); err != nil {
		return nil, errors.Wrap(err, "CBOR Unmarshal node")
	}

	return &node, nil
}

func registryGetNodes(svc service.TendermintService, height int64) ([]*node.Node, error) { // nolint: deadcode, unused
	response, err := svc.Query(registryapp.QueryGetNodes, nil, height)
	if err != nil {
		return nil, errors.Wrapf(err, "Tendermint Query %s", registryapp.QueryGetNodes)
	}

	var nodes []*node.Node
	if err := cbor.Unmarshal(response, &nodes); err != nil {
		return nil, errors.Wrap(err, "CBOR Unmarshal nodes")
	}

	return nodes, nil
}

func schedulerNextElectionHeight(svc service.TendermintService, kind scheduler.CommitteeKind) (int64, error) { // nolint: deadcode, unused
	sub, err := svc.Subscribe("script", schedulerapp.QueryApp)
	if err != nil {
		return 0, errors.Wrap(err, "Tendermint Subscribe")
	}
	defer func() {
		// Drain our unbuffered subscription while we work on unsubscribing.
		go func() {
			for {
				select {
				case <-sub.Out():
				case <-sub.Cancelled():
					break
				}
			}
		}()
		err := svc.Unsubscribe("script", schedulerapp.QueryApp)
		if err != nil {
			panic(fmt.Sprintf("Tendermint Unsubscribe: %+v", err))
		}
	}()

	for {
		ev := (<-sub.Out()).Data().(tmtypes.EventDataNewBlock)
		for _, tmEv := range ev.ResultBeginBlock.GetEvents() {
			if tmEv.GetType() != tmapi.EventTypeEkiden {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), schedulerapp.TagElected) {
					var kinds []scheduler.CommitteeKind
					if err := cbor.Unmarshal(pair.GetValue(), &kinds); err != nil {
						return 0, errors.Wrap(err, "CBOR Unmarshal kinds")
					}

					for _, k := range kinds {
						if k == kind {
							return ev.Block.Header.Height, nil
						}
					}
				}
			}
		}
	}
}

func schedulerGetCommittee(svc service.TendermintService, height int64, kind scheduler.CommitteeKind, runtimeID signature.PublicKey) (*scheduler.Committee, error) { // nolint: deadcode, unused
	raw, err := svc.Query(schedulerapp.QueryKindsCommittees, []scheduler.CommitteeKind{kind}, height)
	if err != nil {
		return nil, errors.Wrapf(err, "Tendermint Query %s", schedulerapp.QueryKindsCommittees)
	}

	var committees []*scheduler.Committee
	if err := cbor.Unmarshal(raw, &committees); err != nil {
		return nil, errors.Wrap(err, "CBOR Unmarshal committees")
	}

	for _, committee := range committees {
		if committee.Kind != kind {
			return nil, errors.Errorf("query returned a committee of the wrong kind %s, expected %s", committee.Kind, kind)
		}

		if !committee.RuntimeID.Equal(runtimeID) {
			continue
		}

		return committee, nil
	}
	return nil, errors.New("query didn't return a committee for our runtime")
}

func schedulerCheckScheduled(committee *scheduler.Committee, nodeID signature.PublicKey, role scheduler.Role) error { // nolint: deadcode, unused
	for _, member := range committee.Members {
		if !member.PublicKey.Equal(nodeID) {
			continue
		}

		if member.Role != role {
			return errors.Errorf("we're scheduled as %s, expected %s", member.Role, role)
		}

		// All good.
		return nil
	}
	return errors.New("we're not scheduled")
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
