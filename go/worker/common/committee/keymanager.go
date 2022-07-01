package committee

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	p2p "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
	keymanagerP2P "github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
)

// KeyManagerClientWrapper is a wrapper for the key manager P2P client that handles deferred
// initialization after the key manager runtime ID is known.
//
// It also handles peer feedback propagation from EnclaveRPC in the runtime.
type KeyManagerClientWrapper struct {
	l sync.Mutex

	id        *common.Namespace
	p2p       p2p.Service
	consensus consensus.Backend
	cli       keymanagerP2P.Client
	logger    *logging.Logger

	lastPeerFeedback rpc.PeerFeedback
}

// Initialized returns a channel that gets closed when the client is initialized.
func (km *KeyManagerClientWrapper) Initialized() <-chan struct{} {
	km.l.Lock()
	defer km.l.Unlock()

	// If no active key manager client, return a closed channel.
	if km.cli == nil {
		initCh := make(chan struct{})
		close(initCh)
		return initCh
	}

	return km.cli.Initialized()
}

// SetKeyManagerID configures the key manager runtime ID to use.
func (km *KeyManagerClientWrapper) SetKeyManagerID(id *common.Namespace) {
	km.l.Lock()
	defer km.l.Unlock()

	// Only reinitialize in case the key manager ID changes.
	if km.id == id || (km.id != nil && km.id.Equal(id)) {
		return
	}

	km.logger.Debug("key manager updated",
		"keymanager_id", id,
	)
	km.id = id

	if km.cli != nil {
		km.cli.Stop()
		km.cli = nil
	}

	if id != nil {
		km.cli = keymanagerP2P.NewClient(km.p2p, km.consensus, *id)
	}

	km.lastPeerFeedback = nil
}

// CallEnclave implements runtimeKeymanager.Client.
func (km *KeyManagerClientWrapper) CallEnclave(
	ctx context.Context,
	data []byte,
	pf *enclaverpc.PeerFeedback,
) ([]byte, error) {
	km.l.Lock()
	cli := km.cli
	lastPf := km.lastPeerFeedback
	km.l.Unlock()

	if cli == nil {
		return nil, fmt.Errorf("key manager not available")
	}

	// Propagate peer feedback on the last EnclaveRPC call to guide routing decision.
	if lastPf != nil {
		// If no feedback has been provided by the runtime, treat previous call as success.
		if pf == nil {
			pfv := enclaverpc.PeerFeedbackSuccess
			pf = &pfv
		}

		km.logger.Debug("received peer feedback from runtime",
			"peer_feedback", *pf,
		)

		switch *pf {
		case enclaverpc.PeerFeedbackSuccess:
			lastPf.RecordSuccess()
		case enclaverpc.PeerFeedbackFailure:
			lastPf.RecordFailure()
		case enclaverpc.PeerFeedbackBadPeer:
			lastPf.RecordBadPeer()
		default:
		}
	}

	rsp, nextPf, err := cli.CallEnclave(ctx, &keymanagerP2P.CallEnclaveRequest{
		Data: data,
	})
	if err != nil {
		return nil, err
	}

	// Store peer feedback instance that we can use.
	km.l.Lock()
	if km.cli == cli { // Key manager could get updated while we are doing the call.
		km.lastPeerFeedback = nextPf
	}
	km.l.Unlock()

	return rsp.Data, nil
}

// NewKeyManagerClientWrapper creates a new key manager client wrapper.
func NewKeyManagerClientWrapper(p2p p2p.Service, consensus consensus.Backend, logger *logging.Logger) *KeyManagerClientWrapper {
	return &KeyManagerClientWrapper{
		p2p:       p2p,
		consensus: consensus,
		logger:    logger,
	}
}
