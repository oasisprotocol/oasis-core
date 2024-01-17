// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

// New constructs a new key manager worker.
func New(
	commonWorker *workerCommon.Worker,
	r *registration.Worker,
	backend api.Backend,
) (*Worker, error) {
	var enabled bool
	switch config.GlobalConfig.Mode {
	case config.ModeKeyManager:
		// When configured in keymanager mode, enable the keymanager worker.
		enabled = true
	default:
		enabled = false
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	w := &Worker{
		logger:              logging.GetLogger("worker/keymanager"),
		ctx:                 ctx,
		cancelCtx:           cancelFn,
		stopCh:              make(chan struct{}),
		quitCh:              make(chan struct{}),
		initCh:              make(chan struct{}),
		clientRuntimes:      make(map[common.Namespace]*clientRuntimeWatcher),
		accessList:          make(map[core.PeerID]map[common.Namespace]struct{}),
		privatePeers:        make(map[core.PeerID]struct{}),
		accessListByRuntime: make(map[common.Namespace][]core.PeerID),
		commonWorker:        commonWorker,
		backend:             backend,
		enabled:             enabled,
		initEnclaveDoneCh:   make(chan *api.SignedInitResponse, 1),
		genMstSecDoneCh:     make(chan bool, 1),
		genMstSecEpoch:      math.MaxUint64,
		genEphSecDoneCh:     make(chan bool, 1),
		genSecHeight:        int64(math.MaxInt64),
	}

	if !w.enabled {
		return w, nil
	}

	initMetrics()

	for _, b64pk := range config.GlobalConfig.Keymanager.PrivatePeerPubKeys {
		pkBytes, err := base64.StdEncoding.DecodeString(b64pk)
		if err != nil {
			return nil, fmt.Errorf("oasis/keymanager: `%s` is not a base64-encoded public key (%w)", b64pk, err)
		}
		var pk signature.PublicKey
		if err = pk.UnmarshalBinary(pkBytes); err != nil {
			return nil, fmt.Errorf("oasis/keymanager: `%s` is not a public key (%w)", b64pk, err)
		}
		peerID, err := p2pAPI.PublicKeyToPeerID(pk)
		if err != nil {
			return nil, fmt.Errorf("oasis/keymanager: `%s` can not be converted to a peer id (%w)", b64pk, err)
		}
		w.privatePeers[peerID] = struct{}{}
	}

	// Parse runtime ID.
	if err := w.runtimeID.UnmarshalHex(config.GlobalConfig.Keymanager.RuntimeID); err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to parse runtime ID: %w", err)
	}
	w.runtimeLabel = w.runtimeID.String()

	var err error
	w.roleProvider, err = r.NewRuntimeRoleProvider(node.RoleKeyManager, w.runtimeID)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create role provider: %w", err)
	}

	w.runtime, err = commonWorker.RuntimeRegistry.NewUnmanagedRuntime(ctx, w.runtimeID)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create runtime registry entry: %w", err)
	}
	if numVers := len(w.runtime.HostVersions()); numVers != 1 {
		return nil, fmt.Errorf("worker/keymanager: expected a single runtime version (got %d)", numVers)
	}

	// Prepare the runtime host node helpers.
	w.RuntimeHostNode, err = runtimeRegistry.NewRuntimeHostNode(w)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create runtime host helpers: %w", err)
	}

	// Register keymanager service.
	commonWorker.P2P.RegisterProtocolServer(p2p.NewServer(commonWorker.ChainContext, w.runtimeID, w))

	return w, nil
}
