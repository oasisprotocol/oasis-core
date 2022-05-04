package committee

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	keymanagerP2P "github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
)

// KeyManagerClientWrapper is a wrapper for the key manager P2P client that handles deferred
// initialization after the key manager runtime ID is known.
type KeyManagerClientWrapper struct {
	l sync.RWMutex

	id  *common.Namespace
	n   *Node
	cli keymanagerP2P.Client
}

// Initialized returns a channel that gets closed when the client is initialized.
func (km *KeyManagerClientWrapper) Initialized() <-chan struct{} {
	km.l.RLock()
	defer km.l.RUnlock()

	// If no active key manager client, return a closed channel.
	if km.cli == nil {
		initCh := make(chan struct{})
		close(initCh)
		return initCh
	}

	return km.cli.Initialized()
}

func (km *KeyManagerClientWrapper) setKeymanagerID(id *common.Namespace) {
	km.l.Lock()
	defer km.l.Unlock()

	// Only reinitialize in case the key manager ID changes.
	if km.id == id || (km.id != nil && km.id.Equal(id)) {
		return
	}

	km.n.logger.Debug("key manager updated",
		"keymanager_id", id,
	)
	km.id = id

	if km.cli != nil {
		km.cli.Stop()
		km.cli = nil
	}

	if id != nil {
		km.cli = keymanagerP2P.NewClient(km.n.P2P, km.n.Consensus, *id)
	}
}

// Implements runtimeKeymanager.Client.
func (km *KeyManagerClientWrapper) CallEnclave(ctx context.Context, data []byte) ([]byte, error) {
	km.l.RLock()
	cli := km.cli
	km.l.RUnlock()

	if cli == nil {
		return nil, fmt.Errorf("key manager not available")
	}

	rsp, pf, err := km.cli.CallEnclave(ctx, &keymanagerP2P.CallEnclaveRequest{
		Data: data,
	})
	if err != nil {
		return nil, err
	}
	// TODO: Support reporting peer feedback from the enclave.
	pf.RecordSuccess()
	return rsp.Data, nil
}

func newKeyManagerClientWrapper(n *Node) *KeyManagerClientWrapper {
	return &KeyManagerClientWrapper{
		n: n,
	}
}
