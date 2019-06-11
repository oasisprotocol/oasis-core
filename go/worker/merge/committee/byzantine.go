package committee

import (
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
)

func (n *Node) byzantineMaybeInjectDiscrepancy(headers []*block.Header) {
	if !n.cfg.ByzantineInjectDiscrepancies {
		return
	}

	n.logger.Error("BYZANTINE MODE: injecting discrepancy into header")

	// Change the state root by adding a new key. We need to actually commit the
	// modified root to storage as we need a storage receipt.
	stateTree, err := urkel.NewWithRoot(n.ctx, n.commonNode.Storage, nil, headers[0].StateRoot)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	err = stateTree.Insert(n.ctx, []byte("__boom__"), []byte("BOOM"))
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	writeLog, newStateRoot, err := stateTree.Commit(n.ctx)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	// NOTE: Order is important for verifying the receipt.
	applyOps := []storage.ApplyOp{
		// I/O root (unchanged).
		storage.ApplyOp{
			Root:            headers[0].IORoot,
			ExpectedNewRoot: headers[0].IORoot,
			WriteLog:        make(storage.WriteLog, 0),
		},
		// State root.
		storage.ApplyOp{
			Root:            headers[0].StateRoot,
			ExpectedNewRoot: newStateRoot,
			WriteLog:        writeLog,
		},
	}

	receipt, err := n.commonNode.Storage.ApplyBatch(n.ctx, applyOps)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	headers[0].StateRoot = newStateRoot
	headers[0].StorageReceipt = receipt.Signature
}
