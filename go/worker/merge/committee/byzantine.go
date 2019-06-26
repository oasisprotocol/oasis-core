package committee

import (
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
)

func (n *Node) byzantineMaybeInjectDiscrepancy(header *block.Header) {
	if !n.cfg.ByzantineInjectDiscrepancies {
		return
	}

	n.logger.Error("BYZANTINE MODE: injecting discrepancy into header")

	// Change the state root by adding a new key. We need to actually commit the
	// modified root to storage as we need a storage receipt.
	stateRoot := storage.Root{
		Namespace: header.Namespace,
		Round:     header.Round,
		Hash:      header.StateRoot,
	}
	stateTree, err := urkel.NewWithRoot(n.ctx, n.commonNode.Storage, nil, stateRoot)
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

	writeLog, newStateRoot, err := stateTree.Commit(n.ctx, header.Namespace, header.Round)
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
			SrcRound: header.Round,
			SrcRoot:  header.IORoot,
			DstRoot:  header.IORoot,
			WriteLog: make(storage.WriteLog, 0),
		},
		// State root.
		storage.ApplyOp{
			SrcRound: header.Round,
			SrcRoot:  header.StateRoot,
			DstRoot:  newStateRoot,
			WriteLog: writeLog,
		},
	}

	receipts, err := n.commonNode.Storage.ApplyBatch(n.ctx, header.Namespace, header.Round, applyOps)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	signatures := []signature.Signature{}
	for _, receipt := range receipts {
		signatures = append(signatures, receipt.Signature)
	}

	header.StateRoot = newStateRoot
	header.StorageSignatures = signatures
}
