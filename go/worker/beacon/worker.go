// Package beacon implements the random beacon worker.
package beacon

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/cenkalti/backoff/v4"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/pvss"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const workerName = "worker/beacon"

var stateStoreKey = []byte("pvss round state")

type roundState struct {
	Epoch beacon.EpochTime  `json:"epoch,omitempty"`
	Round uint64            `json:"round,omitempty"`
	State beacon.RoundState `json:"state,omitempty"`

	Instance *pvss.Instance           `json:"instance,omitempty"`
	CommitTx *transaction.Transaction `json:"commit_tx,omitempty"`
	RevealTx *transaction.Transaction `json:"reveal_tx,omitempty"`
}

type Worker struct {
	sync.Mutex

	ctx context.Context

	logger *logging.Logger

	backend   beacon.PVSSBackend
	identity  *identity.Identity
	consensus consensus.Backend
	registry  registry.Backend

	store *persistent.ServiceStore
	state *roundState

	stopCh      chan struct{}
	quitCh      chan struct{}
	retryCancel context.CancelFunc

	enabled bool
}

func (w *Worker) Start() error {
	if w.enabled {
		go w.worker()
	}

	return nil
}

func (w *Worker) Stop() {
	if !w.enabled {
		close(w.quitCh)
		return
	}

	w.cancelSubmitTx()

	close(w.stopCh)
}

func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *Worker) Cleanup() {
}

func (w *Worker) Name() string {
	return "beacon worker"
}

func (w *Worker) worker() {
	defer func() {
		close(w.quitCh)
	}()

	// Wait for consensus to be synced.
	select {
	case <-w.stopCh:
		return
	case <-w.consensus.Synced():
	}

	// Handle persisted state if required.
	w.recoverPersistedState()

	// Subscribe to PVSS events.
	eventCh, eventSub, err := w.backend.WatchLatestPVSSEvent(w.ctx)
	if err != nil {
		w.logger.Error("failed to subscribe to PVSS events",
			"err", err,
		)
		return
	}
	defer eventSub.Close()

	for {
		var ev *beacon.PVSSEvent
		select {
		case <-w.stopCh:
			return
		case ev = <-eventCh:
			w.logger.Debug("beacon event",
				"height", ev.Height,
				"epoch", ev.Epoch,
				"round", ev.Round,
				"state", ev.State,
			)

			w.cancelSubmitTx()
		}

		// Regardless of what the state transition is, we need to
		// get the backend beacon state.
		pvssState, err := w.backend.GetPVSSState(w.ctx, ev.Height)
		if err != nil {
			w.logger.Error("failed to query PVSS state",
				"err", err,
			)
			continue
		}

		switch ev.State {
		case beacon.StateCommit:
			w.onStateCommit(ev, pvssState)
		case beacon.StateReveal:
			w.onStateReveal(ev, pvssState)
		case beacon.StateComplete:
			w.onStateComplete(ev, pvssState)
		}
	}
}

func (w *Worker) eventOkForState(ev *beacon.PVSSEvent, expectedState beacon.RoundState) bool {
	if w.state == nil {
		return false
	}
	if ev.Epoch != w.state.Epoch || ev.Round != w.state.Round {
		w.logger.Error("epoch/round mismatch",
			"epoch", w.state.Epoch,
			"round", w.state.Round,
		)
		return false
	}
	if w.state.State != expectedState {
		w.logger.Error("round state mismatch",
			"state", w.state.State,
		)
		return false
	}

	return true
}

func (w *Worker) onStateCommit(ev *beacon.PVSSEvent, pvssState *beacon.PVSSState) {
	if w.state != nil {
		if ev.Epoch == w.state.Epoch && ev.Round == w.state.Round {
			// This shouldn't happen, log something about it.
			w.logger.Error("commit: received redundant round event, ignoring")
			return
		}
		w.persistState(nil)
	}

	// New round.

	// Determine if we are present in the participant list, and ensure
	// that the point for each participant are valid.
	var (
		isPresent bool
		points    []pvss.Point
	)
	for _, id := range ev.Participants {
		if id.Equal(w.identity.NodeSigner.Public()) {
			isPresent = true
		}
		node, err := w.registry.GetNode(
			w.ctx,
			&registry.IDQuery{
				Height: ev.Height,
				ID:     id,
			},
		)
		if err != nil {
			w.logger.Error("commit: failed to query node descriptor",
				"err", err,
				"id", id,
			)
			return
		}
		if node.Beacon == nil {
			w.logger.Error("commit: participant node missing point",
				"id", id,
			)
			return
		}
		points = append(points, node.Beacon.Point)
	}
	h, cmpH := hash.NewFrom(points), hash.NewFrom(pvssState.Instance.Participants)
	if !h.Equal(&cmpH) {
		w.logger.Error("commit: participant point list mismatch")
		return
	}
	if !isPresent {
		w.logger.Info("commit: node is not present in participant list")
		return
	}

	// Initialize the local PVSS instance.
	instance, err := pvss.New(&pvss.Config{
		PrivateKey:   &w.identity.BeaconScalar,
		Participants: points,
		Threshold:    pvssState.Instance.Threshold,
	})
	if err != nil {
		w.logger.Error("commit: failed to initialize PVSS instance",
			"err", err,
		)
		return
	}

	// Generate the commit.
	commit, err := instance.Commit()
	if err != nil {
		w.logger.Error("commit: failed to generate commit",
			"err", err,
		)
		return
	}
	commitPayload := beacon.PVSSCommit{
		Epoch:  ev.Epoch,
		Round:  ev.Round,
		Commit: commit,
	}
	tx := transaction.NewTransaction(0, nil, beacon.MethodPVSSCommit, commitPayload)

	// Persist so it is possible to recover.
	w.persistState(&roundState{
		Epoch:    ev.Epoch,
		Round:    ev.Round,
		State:    ev.State,
		Instance: instance,
		CommitTx: tx,
	})

	// Submit the commit tx.
	w.retrySubmitTx(tx)
}

func (w *Worker) onStateReveal(ev *beacon.PVSSEvent, pvssState *beacon.PVSSState) {
	var stateOk bool
	defer func() {
		if !stateOk {
			w.persistState(nil)
		}
	}()

	if !w.eventOkForState(ev, beacon.StateCommit) {
		return
	}

	if pvssState.BadParticipants[w.identity.NodeSigner.Public()] {
		w.logger.Error("reveal: node identity listed as bad participant")
		return
	}

	// Handle all of the commits.
	//
	// Note: This could be better optimized by having the consensus layer
	// broadcast events on each commit received to spread the workload out
	// over time, but doing it this way is a lot simpler.
	for i := 0; i < len(pvssState.Participants); i++ {
		cs := pvssState.Instance.Commits[i]
		if cs == nil {
			if w.state.Instance.Commits[i] != nil {
				// More than likely, this is our commit that is missing,
				// but we should have been BadParticipants-ed.
				w.logger.Error("reveal: BUG: consensus instance missing commit",
					"participant_index", i,
				)
				return
			}
			continue
		}
		if oldCommit := w.state.Instance.Commits[i]; oldCommit != nil {
			oldHash, newHash := hash.NewFrom(oldCommit.Commit), hash.NewFrom(cs.Commit)
			if !oldHash.Equal(&newHash) {
				w.logger.Error("reveal: existing commit changed",
					"participant_index", i,
				)
				return
			}
			continue
		}

		// Process the external commitment.
		if err := w.state.Instance.OnCommit(cs.Commit); err != nil {
			w.logger.Error("reveal: failed to process commit",
				"err", err,
				"participant_index", i,
			)
			return
		}
	}

	// Generate the reveal.
	if ok, totalCommits := w.state.Instance.MayReveal(); !ok {
		w.logger.Error("reveal: BUG: insufficient commits for reveal",
			"total_commits", totalCommits,
		)
		return
	}
	reveal, err := w.state.Instance.Reveal()
	if err != nil {
		w.logger.Error("reveal: failed to generate reveal",
			"err", err,
		)
		return
	}
	revealPayload := beacon.PVSSReveal{
		Epoch:  ev.Epoch,
		Round:  ev.Round,
		Reveal: reveal,
	}
	tx := transaction.NewTransaction(0, nil, beacon.MethodPVSSReveal, revealPayload)

	// Persist so it is possible to recover.
	w.state.State = beacon.StateReveal
	w.state.RevealTx = tx
	w.persistState(w.state)
	stateOk = true

	// Submit the reveal.
	w.retrySubmitTx(tx)
}

func (w *Worker) onStateComplete(ev *beacon.PVSSEvent, pvssState *beacon.PVSSState) {
	defer w.persistState(nil) // Round is finished, clear state when done.
	if !w.eventOkForState(ev, beacon.StateReveal) {
		return
	}

	// Technically, this can just clear the state, since the entropy was
	// generated for this round, but it doesn't hurt to check the output
	// since it's easy to do.
	//
	// This could be done unconditionally since the output is publicly
	// verifiable...

	// Handle all of the reveals.
	for i := 0; i < len(pvssState.Participants); i++ {
		reveal := pvssState.Instance.Reveals[i]
		if reveal == nil {
			if w.state.Instance.Reveals[i] != nil {
				// More than likely, we failed to submit our reveal,
				// but this is non-fatal for the purpose of validation.
				w.logger.Error("recover: consensus instance missing reveal",
					"participant_index", i,
				)
			}
			continue
		}
		if oldReveal := w.state.Instance.Reveals[i]; oldReveal != nil {
			oldHash, newHash := hash.NewFrom(oldReveal), hash.NewFrom(reveal)
			if !oldHash.Equal(&newHash) {
				w.logger.Error("recover: existing commit changed",
					"participant_index", i,
				)
				return
			}
			continue
		}

		if err := w.state.Instance.OnReveal(reveal); err != nil {
			w.logger.Error("recover: failed to process reveal",
				"err", err,
				"participant_index", i,
			)
			return
		}
	}

	// Recover the entropy, and cross-check the output.
	if ok, totalReveals := w.state.Instance.MayRecover(); !ok {
		w.logger.Error("recover: BUG: insufficient reveals for recover",
			"total_reveals", totalReveals,
		)
		return
	}
	entropy, _, err := w.state.Instance.Recover()
	if err != nil {
		w.logger.Error("recover: failed to generate entropy",
			"err", err,
		)
		return
	}
	if !bytes.Equal(pvssState.Entropy, entropy) {
		w.logger.Error("recover: BUG: entropy mismatch",
			"recovered", entropy,
			"expected", pvssState.Entropy,
		)
	}
}

func (w *Worker) recoverPersistedState() {
	var state roundState
	if err := w.store.GetCBOR(stateStoreKey, &state); err != nil {
		w.logger.Error("restore: failed to get persisted state",
			"err", err,
		)
		return
	}

	pvssState, err := w.backend.GetPVSSState(w.ctx, consensus.HeightLatest)
	if err != nil {
		w.logger.Error("restore: failed to query PVSS state",
			"err", err,
		)
		return
	}
	if pvssState == nil {
		w.logger.Debug("restore: no consensus state, round presumably complete")
		w.persistState(nil)
		return
	}

	// The round finished while we weren't looking, nothing to be done.
	if pvssState.State == beacon.StateComplete {
		w.logger.Debug("restore: consensus round is complete, ignoring persisted state")
		w.persistState(nil)
		return
	}

	// The round transitioned while the node was offline.
	if pvssState.Epoch != state.Epoch || pvssState.Round != state.Round {
		if pvssState.State != beacon.StateCommit {
			// Can't catch up.  The current round isn't accepting commits.
			w.logger.Debug("restore: consensus round won't accept commits, can't catch up")
			w.persistState(nil)
			return
		}

		// Just handle this as a commit event for a new round.
		w.logger.Debug("restore: new round, attempting to catch up")

		var ev beacon.PVSSEvent
		ev.FromState(pvssState)
		w.onStateCommit(&ev, pvssState)
		return
	}

	// Epoch/round is still the same at this point, so set the instance
	// scalar, since we can resume using the persisted instance.
	if err = state.Instance.SetScalar(&w.identity.BeaconScalar); err != nil {
		w.logger.Error("restore: failed to set instance scalar",
			"err", err,
		)
		w.persistState(nil)
		return
	}

	w.state = &state // The persisted round state is usable.
	if pvssState.State == state.State {
		// The consensus state is on the same step as our persisted state.

		w.logger.Debug("restore: round and step are the same, view caught up")

		// Check to see if we successfully submitted the appropriate tx,
		// and re-submit as required.
		participantIndex := -1
		for idx, id := range pvssState.Participants {
			if id.Equal(w.identity.NodeSigner.Public()) {
				participantIndex = idx
				break
			}
		}
		if participantIndex < 0 {
			w.logger.Error("restore: failed to find participant index")
			w.persistState(nil)
			return
		}

		var tx *transaction.Transaction
		switch state.State {
		case beacon.StateCommit:
			if pvssState.Instance.Commits[participantIndex] == nil {
				tx = state.CommitTx
			}
		case beacon.StateReveal:
			if pvssState.Instance.Reveals[participantIndex] == nil {
				tx = state.RevealTx
			}
		}
		if tx != nil {
			w.logger.Debug("restore: resubmitting tx")
			w.retrySubmitTx(tx)
		}

		return
	}

	// The consensus state advanced past where we last were, so attempt
	// to catch up if possible.  This is guaranteed to be a commit->
	// reveal transition, since we would have bailed early if the round
	// completed.
	if pvssState.State != beacon.StateReveal || state.State != beacon.StateCommit {
		w.logger.Error("restore: unexpected consensus/local state for resumption",
			"state", state.State,
			"consesus_state", pvssState.State,
		)
		w.persistState(nil)
		return
	}

	w.logger.Debug("restore: transitioned to reveal, attempting to catch up")

	var ev beacon.PVSSEvent
	ev.FromState(pvssState)
	w.onStateReveal(&ev, pvssState)
}

func (w *Worker) persistState(newState *roundState) {
	w.state = newState

	if newState == nil {
		if err := w.store.Delete(stateStoreKey); err != nil {
			w.logger.Error("failed to clear state from local store",
				"err", err,
			)
		}
		return
	}

	if err := w.store.PutCBOR(stateStoreKey, newState); err != nil {
		w.logger.Error("failed to persist state to local store",
			"err", err,
		)
	}
}

func (w *Worker) newRetryCtx() context.Context {
	w.Lock()
	defer w.Unlock()

	if w.retryCancel != nil {
		w.retryCancel()
	}

	var ctx context.Context
	ctx, w.retryCancel = context.WithCancel(w.ctx)

	return ctx
}

func (w *Worker) cancelSubmitTx() {
	w.Lock()
	defer w.Unlock()

	if w.retryCancel != nil {
		w.retryCancel()
		w.retryCancel = nil
	}
}

func (w *Worker) retrySubmitTx(tx *transaction.Transaction) {
	ctx := w.newRetryCtx()
	expOff := backoff.NewExponentialBackOff()
	expOff.MaxElapsedTime = 0
	off := backoff.WithContext(expOff, ctx)

	fn := func() error {
		// Query state to make sure submitting the tx is still sensible.
		pvssState, err := w.backend.GetPVSSState(ctx, consensus.HeightLatest)
		if err != nil {
			return err
		}

		expectedState := beacon.StateInvalid
		switch tx.Method {
		case beacon.MethodPVSSCommit:
			// This will retry the tx submission if the round has failed in
			// the commit phase, but it kind of doesn't matter since the
			// round state changing will cancel ctx.
			expectedState = beacon.StateCommit
		case beacon.MethodPVSSReveal:
			expectedState = beacon.StateReveal
		}
		if pvssState.State != expectedState {
			return backoff.Permanent(fmt.Errorf("worker/beacon: state not expected for tx: %s", pvssState.State))
		}

		// Try the tx submission.
		err = consensus.SignAndSubmitTx(ctx, w.consensus, w.identity.NodeSigner, tx)
		if err == nil {
			w.logger.Debug("tx submitted",
				"method", tx.Method,
			)
		}

		return err
	}

	// Optimistically try to just submit the Tx in-line.
	if err := fn(); err != nil {
		w.logger.Debug("in-line tx submit failed, scheduling retries",
			"err", err,
			"method", tx.Method,
		)

		go backoff.Retry(fn, off) //nolint: errcheck
	}
}

// New creates a new worker instance.
func New(
	identity *identity.Identity,
	consensus consensus.Backend,
	store *persistent.CommonStore,
) (*Worker, error) {
	if identity.BeaconScalar.Inner() == nil {
		return nil, fmt.Errorf("worker/beacon: identity does not provide a scalar")
	}

	serviceStore, err := store.GetServiceStore(workerName)
	if err != nil {
		return nil, fmt.Errorf("worker/beacon: failed to get persistent store bucket: %w", err)
	}

	pvssBackend, shouldEnable := consensus.Beacon().(beacon.PVSSBackend)

	w := &Worker{
		ctx:       context.Background(),
		logger:    logging.GetLogger(workerName),
		backend:   pvssBackend,
		identity:  identity,
		consensus: consensus,
		registry:  consensus.Registry(),
		store:     serviceStore,
		state:     nil,
		stopCh:    make(chan struct{}),
		quitCh:    make(chan struct{}),
		enabled:   shouldEnable,
	}

	return w, nil
}
