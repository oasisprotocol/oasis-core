package txpool

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

var (
	_ UsableTransactionSource = (*rimQueue)(nil)
)

// rimQueue exposes transactions form roothash incoming messages.
type rimQueue struct{}

func (rq *rimQueue) GetSchedulingSuggestion() [][]byte {
	// Runtimes instead get transactions from the incoming messages.
	return nil
}

func (rq *rimQueue) GetTxByHash(h hash.Hash) ([]byte, bool) {
	// TODO implement me
	panic("implement me")
	// get incoming messages, parse them, extract txs, hash them, look up by hash here
}

func (rq *rimQueue) HandleTxsUsed(hashes []hash.Hash) {
	// The roothash module manages the incoming message queue on its own, so we don't do anything here.
}

// Load loads transactions from roothash incoming messages.
func (rq *rimQueue) Load() {
	// todo: get access to all this various stuff
	inMsgs, err := n.commonNode.Consensus.RootHash().GetIncomingMessageQueue(ctx, &roothash.InMessageQueueRequest{
		RuntimeID: n.commonNode.Runtime.ID(),
		Height:    consensusBlk.Height,
	})
	if err != nil {
		n.logger.Error("failed to fetch incoming runtime message queue transactions",
			"err", err,
		)
		// todo: propagate sanely
		panic(err)
	}
	var inMsgTxs [][]byte
	for _, msg := range inMsgs {
		var data message.IncomingMessageData
		if err = cbor.Unmarshal(msg.Data, &data); err != nil {
			n.logger.Warn("incoming message data unmarshal failed",
				"id", msg.ID,
				"err", err,
			)
			continue
		}
		if err = data.ValidateBasic(); err != nil {
			n.logger.Warn("incoming message data validate failed",
				"id", msg.ID,
				"err", err,
			)
		}
		if data.Transaction != nil {
			inMsgTxs = append(inMsgTxs, *data.Transaction)
		}
	}
	// todo: store inMsgTxs until next block
}
