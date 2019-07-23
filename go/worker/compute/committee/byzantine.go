package committee

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

func (n *Node) byzantineMaybeInjectDiscrepancy(inputs runtime.Batch) (writelog.WriteLog, hash.Hash, error) {
	if !n.cfg.ByzantineInjectDiscrepancies {
		return nil, hash.Hash{}, nil
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
		return nil, hash.Hash{}, err
	}

	header := n.commonNode.CurrentBlock.Header
	return ioTree.Commit(n.ctx, header.Namespace, header.Round+1)
}
