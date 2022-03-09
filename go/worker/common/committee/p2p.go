package committee

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

type txMsgHandler struct {
	n *Node
}

func (h *txMsgHandler) DecodeMessage(msg []byte) (interface{}, error) {
	var tx []byte
	if err := cbor.Unmarshal(msg, &tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func (h *txMsgHandler) AuthorizeMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}) error {
	// Everyone is allowed to publish transactions.
	return nil
}

func (h *txMsgHandler) HandleMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}, isOwn bool) error {
	// Ignore own messages as those are handled separately.
	if isOwn {
		return nil
	}

	tx := msg.([]byte) // Ensured by DecodeMessage.

	switch h.n.Runtime.Mode() {
	case runtimeRegistry.RuntimeModeClientStateless:
		// Ignore transactions on stateless clients.
	default:
		// Queue in local transaction pool if we are not running a stateless client.
		result, err := h.n.TxPool.SubmitTx(ctx, tx, &txpool.TransactionMeta{Local: false})
		switch {
		case err != nil:
			return p2pError.Permanent(err)
		case !result.IsSuccess():
			return p2pError.Permanent(fmt.Errorf("transaction check failed: %s", result.Error))
		default:
		}
	}

	// Dispatch to any transaction handlers.
	for _, hooks := range h.n.hooks {
		if err := hooks.HandlePeerTx(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}

// PublishTx publishes a transaction via P2P gossipsub.
func (n *Node) PublishTx(ctx context.Context, tx []byte) error {
	n.P2P.PublishTx(ctx, n.Runtime.ID(), tx)
	return nil
}

// GetMinRepublishInterval returns the minimum republish interval that needs to be respected by
// the caller when publishing the same message. If Publish is called for the same message more
// quickly, the message may be dropped and not published.
func (n *Node) GetMinRepublishInterval() time.Duration {
	return n.P2P.GetMinRepublishInterval()
}
