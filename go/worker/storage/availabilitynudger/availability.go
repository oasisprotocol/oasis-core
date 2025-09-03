// Package availabilitynudger defines logic for updating the role providers.
package availabilitynudger

import (
	"context"
	"fmt"
	"math"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/statesync"
)

const (
	// The maximum number of rounds the worker can be behind the chain before it's sensible for
	// it to register as available.
	maximumRoundDelayForAvailability = uint64(10)

	// The minimum number of rounds the worker can be behind the chain before it's sensible for
	// it to stop advertising availability.
	minimumRoundDelayForUnavailability = uint64(15)
)

// Worker tracks the progress of last and last synced rounds
// and “nudges” role providers to mark themselves available or unavailable
// based on how closely the node is keeping up with consensus.
type Worker struct {
	roleProvider    registration.RoleProvider
	rpcRoleProvider registration.RoleProvider
	roleAvailable   bool

	lastRound       uint64
	lastSyncedRound uint64

	blockCh   *channels.InfiniteChannel
	stateSync *statesync.Worker

	logger *logging.Logger
}

// New creates a new worker that updates the availability to role providers.
func New(localProvider, rpcProvider registration.RoleProvider, blockCh *channels.InfiniteChannel, stateSync *statesync.Worker, runtimeID common.Namespace) *Worker {
	return &Worker{
		roleProvider:    localProvider,
		rpcRoleProvider: rpcProvider,
		lastRound:       math.MaxUint64,
		lastSyncedRound: math.MaxUint64,
		blockCh:         blockCh,
		stateSync:       stateSync,
		logger:          logging.GetLogger("worker/storage/availabilitynudger").With("runtime_id", runtimeID),
	}
}

// Serve starts the worker.
func (w *Worker) Serve(ctx context.Context) error {
	w.logger.Info("started")
	defer w.logger.Info("stopped")

	finalizeCh, sub, err := w.stateSync.WatchFinalizedRounds()
	if err != nil {
		return fmt.Errorf("failed to watch finalized rounds: %w", err)
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case inBlk := <-w.blockCh.Out():
			blk := inBlk.(*block.Block)
			w.setLastRound(blk.Header.Round)
		case round := <-finalizeCh:
			w.setLastSyncedRound(round)
		}
		w.updateAvailability()
	}
}

// setLastRound updates the last round number.
func (w *Worker) setLastRound(round uint64) {
	w.lastRound = round
}

// setLastSyncedRound updates the most recently synced round number.
func (w *Worker) setLastSyncedRound(round uint64) {
	w.lastSyncedRound = round
}

// updateAvailability updates the role's availability based on the gap
// between the last round and the last synced round.
func (w *Worker) updateAvailability() {
	if w.lastRound == math.MaxUint64 || w.lastSyncedRound == math.MaxUint64 {
		return
	}
	// if w.lastRound > w.lastSyncedRound {
	// 	return
	// } not sure what was intent here given this we are looking for the gap.

	switch roundLag := w.lastRound - w.lastSyncedRound; {
	case roundLag < maximumRoundDelayForAvailability:
		w.markAvailable()
	case roundLag > minimumRoundDelayForUnavailability:
		w.markUnavailable()
	}
}

// markAvailable sets the role as available if it is not already.
func (w *Worker) markAvailable() {
	if w.roleAvailable {
		return
	}
	w.roleAvailable = true

	w.logger.Info("marking as available")

	if w.roleProvider != nil {
		w.roleProvider.SetAvailable(func(*node.Node) error { return nil })
	}
	if w.rpcRoleProvider != nil {
		w.rpcRoleProvider.SetAvailable(func(*node.Node) error { return nil })
	}
}

// markUnavailable sets the role as unavailable if it is currently available.
func (w *Worker) markUnavailable() {
	if !w.roleAvailable {
		return
	}
	w.roleAvailable = false

	w.logger.Info("marking as unavailable")

	if w.roleProvider != nil {
		w.roleProvider.SetUnavailable()
	}
	if w.rpcRoleProvider != nil {
		w.rpcRoleProvider.SetUnavailable()
	}
}
