package full

import (
	"context"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

type failMonitor struct {
	sync.Mutex

	isCleanShutdown bool
}

func (m *failMonitor) markCleanShutdown() {
	m.Lock()
	defer m.Unlock()

	m.isCleanShutdown = true
}

func newFailMonitor(ctx context.Context, logger *logging.Logger, fn func()) *failMonitor {
	// Tendermint in it's infinite wisdom, doesn't terminate when
	// consensus fails, instead opting to "just" log, and tear down
	// the ConsensusState.  Since this behavior is stupid, watch for
	// unexpected ConsensusState termination, and panic to kill the
	// Oasis node.

	var m failMonitor
	go func() {
		// Wait(), basically.
		fn()

		// Check to see if the termination was expected or not.
		m.Lock()
		defer m.Unlock()

		if !m.isCleanShutdown && ctx.Err() == nil {
			logger.Error("unexpected termination detected")
			panic("tendermint: unexpected termination detected, consensus failure?")
		}
	}()

	return &m
}
