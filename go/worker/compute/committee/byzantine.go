package committee

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

func (n *Node) byzantineMaybeInjectDiscrepancy(
	ctx context.Context,
	ioRoot hash.Hash,
	batch *protocol.ComputedBatch,
	blk *block.Block,
) {
	if !n.cfg.ByzantineInjectDiscrepancies {
		return
	}

	n.logger.Error("BYZANTINE MODE: injecting discrepancy into batch")

	// Inject bogus write log entry.
	batch.IOWriteLog = append(batch.IOWriteLog, writelog.LogEntry{Key: []byte("__boom__"), Value: []byte("poof")})

	// Compute updated I/O root.
	tree := urkel.NewWithRoot(n.commonNode.Storage, nil, node.Root{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round + 1,
		Hash:      ioRoot,
	})
	defer tree.Close()

	err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(batch.IOWriteLog))
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return
	}

	// Compute the new I/O root.
	_, batch.Header.IORoot, err = tree.Commit(ctx, blk.Header.Namespace, blk.Header.Round+1)
	if err != nil {
		n.logger.Error("failed to inject discrepancy",
			"err", err,
		)
		return
	}
}
