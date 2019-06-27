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

	writeLog, newIoRoot, err := ioTree.Commit(n.ctx)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return err
	}

	_, err = n.commonNode.Storage.Apply(n.ctx, oldIoRoot, newIoRoot, writeLog)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return err
	}

	*ioRoot = newIoRoot

	return nil
}
