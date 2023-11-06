package committee

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/config"
	p2pError "github.com/oasisprotocol/oasis-core/go/p2p/error"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
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

func (h *txMsgHandler) AuthorizeMessage(context.Context, signature.PublicKey, interface{}) error {
	// Everyone is allowed to publish transactions.
	return nil
}

func (h *txMsgHandler) HandleMessage(ctx context.Context, _ signature.PublicKey, msg interface{}, isOwn bool) error {
	// Ignore own messages as those are handled separately.
	if isOwn {
		return nil
	}

	tx := msg.([]byte) // Ensured by DecodeMessage.

	switch config.GlobalConfig.Mode {
	case config.ModeStatelessClient:
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

	return nil
}

// PublishTx publishes a transaction via P2P gossipsub.
func (n *Node) PublishTx(ctx context.Context, tx []byte) error {
	n.P2P.Publish(ctx, n.txTopic, tx)
	return nil
}

// GetMinRepublishInterval returns the minimum republish interval that needs to be respected by
// the caller when publishing the same message. If Publish is called for the same message more
// quickly, the message may be dropped and not published.
func (n *Node) GetMinRepublishInterval() time.Duration {
	return n.P2P.GetMinRepublishInterval()
}
