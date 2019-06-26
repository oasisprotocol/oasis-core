package committee

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
)

func (n *Node) byzantineMaybeInjectDiscrepancy(ioRoot *hash.Hash, inputs runtime.Batch) error {
	if !n.cfg.ByzantineInjectDiscrepancies {
		return nil
	}

	n.logger.Error("BYZANTINE MODE: injecting discrepancy into batch")

	for i := range inputs {
		inputs[i] = []byte("boom")
	}

	// Update the I/O root as otherwise the runtime will complain.
	var oldIoRoot hash.Hash
	oldIoRoot.Empty()
	ioTree := urkel.New(nil, nil)
	err := ioTree.Insert(n.ctx, block.IoKeyInputs, inputs.MarshalCBOR())
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return err
	}

	header := n.commonNode.CurrentBlock.Header
	writeLog, newIoRoot, err := ioTree.Commit(n.ctx, header.Namespace, header.Round+1)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return err
	}

	_, err = n.commonNode.Storage.Apply(
		n.ctx,
		header.Namespace,
		header.Round+1,
		oldIoRoot,
		header.Round+1,
		newIoRoot,
		writeLog,
	)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return err
	}

	*ioRoot = newIoRoot

	return nil
}
