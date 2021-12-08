package beacon

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/cenkalti/backoff/v4"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

type vrfWorker struct {
	parent *Worker
	logger *logging.Logger

	backend beacon.VRFBackend
	txRetry *txRetry

	stopCh chan struct{}
	quitCh chan struct{}

	enabled bool
}

func (w *vrfWorker) Start() error {
	if w.enabled {
		go w.worker()
	}

	return nil
}

func (w *vrfWorker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	w.txRetry.Cancel()

	close(w.stopCh)
}

func (w *vrfWorker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *vrfWorker) Cleanup() {
}

func (w *vrfWorker) worker() {
	defer func() {
		close(w.quitCh)
	}()

	// Wait for consensus to be synced.
	select {
	case <-w.stopCh:
		return
	case <-w.parent.consensus.Synced():
	}

	// Subscribe to VRF events.
	eventCh, eventSub, err := w.backend.WatchLatestVRFEvent(w.parent.ctx)
	if err != nil {
		w.logger.Error("failed to subscribe to VRF events",
			"err", err,
		)
		return
	}
	defer eventSub.Close()

	// Subscribe to block height events.
	blockCh, blockSub, err := w.parent.consensus.WatchBlocks(w.parent.ctx)
	if err != nil {
		w.logger.Error("failed to subscribe to block events",
			"err", err,
		)
		return
	}
	defer blockSub.Close()

	var (
		ev     *beacon.VRFEvent
		height int64
	)
	for {
		select {
		case <-w.stopCh:
			return
		case ev = <-eventCh:
			w.logger.Debug("VRF event",
				"epoch", ev.Epoch,
				"alpha", hex.EncodeToString(ev.Alpha),
				"submit_after", ev.SubmitAfter,
			)
			w.txRetry.Cancel()
		case blk := <-blockCh:
			height = blk.Height
		}

		// Check that it appears to be sensible to submit a proof.
		if ev == nil || height < ev.SubmitAfter {
			continue
		}

		// Re-query the current block height.
		blk, err := w.parent.consensus.GetBlock(w.parent.ctx, consensus.HeightLatest)
		if err != nil {
			w.logger.Error("failed to query latest block",
				"err", err,
			)
			continue
		}
		height = blk.Height

		// Query the current VRF state.
		vrfState, err := w.backend.GetVRFState(w.parent.ctx, height)
		if err != nil {
			w.logger.Error("failed to query VRF state",
				"err", err,
			)
			continue
		}
		if vrfState == nil {
			w.logger.Error("VRF state is nil")
			continue
		}

		// Ensure that it actually is a good idea to submit a proof.
		if height < vrfState.SubmitAfter {
			continue
		}
		if vrfState.Pi != nil {
			if pi := vrfState.Pi[w.parent.identity.NodeSigner.Public()]; pi != nil {
				w.logger.Error("already submitted VRF proof",
					"pi", pi,
				)
				ev = nil // Don't attempt to handle this event anymore.
				continue
			}
		}

		// Generate the proof and transaction.
		pi, err := signature.Prove(w.parent.identity.VRFSigner, vrfState.Alpha)
		if err != nil {
			w.logger.Error("failed to generate VRF proof",
				"err", err,
			)
			continue
		}
		proofPayload := beacon.VRFProve{
			Epoch: vrfState.Epoch,
			Pi:    pi.Proof[:],
		}
		tx := transaction.NewTransaction(0, nil, beacon.MethodVRFProve, proofPayload)

		// Kick off the tx, and clear the event since we handled it.
		w.retrySubmitTx(tx, vrfState.Epoch)
		ev = nil
	}
}

func (w *vrfWorker) retrySubmitTx(tx *transaction.Transaction, epoch beacon.EpochTime) {
	checkFn := func(ctx context.Context) error {
		// Query state to make sure submitting the tx is still sensible.
		vrfState, err := w.backend.GetVRFState(ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}
		if vrfState == nil {
			return backoff.Permanent(fmt.Errorf("worker/beacon: VRF state is nil"))
		}

		if vrfState.Epoch != epoch {
			return backoff.Permanent(fmt.Errorf("worker/beacon: epoch changed: %d", vrfState.Epoch))
		}

		return nil
	}

	w.txRetry.SubmitTx(w.parent.ctx, tx, checkFn)
}

func newVRF(parent *Worker) (*vrfWorker, error) {
	if parent.identity.VRFSigner == nil {
		return nil, fmt.Errorf("worker/beacon: identity does not provide a VRF signer")
	}

	vrfBackend, shouldEnable := parent.consensus.Beacon().(beacon.VRFBackend)

	w := &vrfWorker{
		parent:  parent,
		logger:  logging.GetLogger(workerName + "/vrf"),
		backend: vrfBackend,
		stopCh:  make(chan struct{}),
		quitCh:  make(chan struct{}),
		enabled: shouldEnable,
	}
	w.txRetry = newTxRetry(w.logger, parent.consensus, parent.identity)

	return w, nil
}
