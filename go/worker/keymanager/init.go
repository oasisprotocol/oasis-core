// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/libp2p/go-libp2p/core"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	// CfgRuntimeID configures the runtime ID.
	CfgRuntimeID = "worker.keymanager.runtime.id"
	// CfgMayGenerate allows the enclave to generate a master secret.
	CfgMayGenerate = "worker.keymanager.may_generate"
	// CfgPrivatePeerPubKeys allows adding manual, unadvertised peers that can call protected methods.
	CfgPrivatePeerPubKeys = "worker.keymanager.private_peer_pub_keys"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new key manager worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	ias ias.Endpoint,
	r *registration.Worker,
	backend api.Backend,
) (*Worker, error) {
	var enabled bool
	switch commonWorker.RuntimeRegistry.Mode() {
	case runtimeRegistry.RuntimeModeKeymanager:
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
		initTickerCh:        nil,
		clientRuntimes:      make(map[common.Namespace]*clientRuntimeWatcher),
		accessList:          make(map[core.PeerID]map[common.Namespace]struct{}),
		privatePeers:        make(map[core.PeerID]struct{}),
		accessListByRuntime: make(map[common.Namespace][]core.PeerID),
		commonWorker:        commonWorker,
		backend:             backend,
		enabled:             enabled,
		mayGenerate:         viper.GetBool(CfgMayGenerate),
	}

	if !w.enabled {
		return w, nil
	}

	initMetrics()

	for _, b64pk := range viper.GetStringSlice(CfgPrivatePeerPubKeys) {
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

	var runtimeID common.Namespace
	if err := runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID)); err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to parse runtime ID: %w", err)
	}

	var err error
	w.roleProvider, err = r.NewRuntimeRoleProvider(node.RoleKeyManager, runtimeID)
	if err != nil {
		return nil, fmt.Errorf("worker/keymanager: failed to create role provider: %w", err)
	}

	w.runtime, err = commonWorker.RuntimeRegistry.NewUnmanagedRuntime(ctx, runtimeID)
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
	commonWorker.P2P.RegisterProtocolServer(p2p.NewServer(runtimeID, w))

	return w, nil
}

func init() {
	Flags.String(CfgRuntimeID, "", "Key manager Runtime ID")
	Flags.Bool(CfgMayGenerate, false, "Key manager may generate new master secret")
	Flags.StringSlice(CfgPrivatePeerPubKeys, []string{}, "b64-encoded public keys of unadvertised peers that may call protected methods")

	_ = viper.BindPFlags(Flags)
}
