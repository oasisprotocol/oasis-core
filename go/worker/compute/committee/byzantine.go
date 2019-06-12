package committee

import (
	"github.com/oasislabs/ekiden/go/common/runtime"
)

func (n *Node) byzantineMaybeInjectDiscrepancy(calls runtime.Batch) {
	if !n.cfg.ByzantineInjectDiscrepancies {
		return
	}

	n.logger.Error("BYZANTINE MODE: injecting discrepancy into batch")

	for i := range calls {
		calls[i] = []byte("boom")
	}
}
