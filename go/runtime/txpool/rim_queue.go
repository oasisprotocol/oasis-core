package txpool

import "github.com/oasisprotocol/oasis-core/go/common/crypto/hash"

var _ UsableTransactionSource = (*rimQueue)(nil)

// rimQueue exposes transactions form roothash incoming messages.
type rimQueue struct{}

func newRimQueue() *rimQueue {
	return &rimQueue{}
}

func (rq *rimQueue) GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta {
	// Runtimes instead get transactions from the incoming messages.
	return nil
}

func (rq *rimQueue) GetTxByHash(h hash.Hash) (*TxQueueMeta, bool) {
	// TODO implement me
	panic("implement me")
	// get incoming messages, parse them, extract txs, hash them, look up by hash here
}

func (rq *rimQueue) HandleTxsUsed(hashes []hash.Hash) {
	// The roothash module manages the incoming message queue on its own, so we don't do anything here.
}
