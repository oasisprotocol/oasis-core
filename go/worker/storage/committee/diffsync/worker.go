package diffsync

import (
	"context"
	"errors"
	"fmt"

	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"golang.org/x/sync/errgroup"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
)

type Fetcher interface {
	Next(ctx context.Context) (Diff, error)
	Accept()
	Reject()
}

// Diff has a writelog, so that applying it to the state with prevRoot
// produces a new state that corresponds to thisRoot.
type Diff struct {
	round    uint64
	prevRoot storageApi.Root
	thisRoot storageApi.Root
	writeLog storageApi.WriteLog
}

type Finalized struct {
	Round uint64
	Roots []storageApi.Root
}

type Worker struct {
	logger       *logging.Logger
	fetcher      Fetcher
	localStorage storageApi.LocalBackend
	updates      chan Finalized
}

// New creates a new diff sync worker.
//
// Fetcher implements fetching storage diffs, that are then applied ot the localStorage.
func New(history history.History, localStorage storageApi.LocalBackend, fetcher Fetcher) *Worker {
	return &Worker{
		logger:       logging.GetLogger("worker/storage/committee/diffsync").With("runtime_id", history.RuntimeID()),
		localStorage: localStorage,
		fetcher:      fetcher,
		updates:      make(chan Finalized, 1),
	}
}

func (w *Worker) Updates() <-chan Finalized {
	return w.updates
}

// Serve fetches, applies and finalizes storage diffs.
func (w *Worker) Serve(ctx context.Context) error {
	defer close(w.updates)

	w.logger.Info("starting")
	defer w.logger.Info("stopping")

	g, ctx := errgroup.WithContext(ctx)

	appliedCh := make(chan []storageApi.Root, dbApi.MaxPendingVersions)
	defer close(appliedCh)

	// Apply.
	g.Go(func() error {
		var applied []storageApi.Root
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			diff, err := w.fetcher.Next(ctx)
			if err != nil {
				w.logger.Error("fetcher failed to fetch next diff", "err", err)
				continue
			}

			// If thisRoot already exists then localStorage.Apply ignores request.
			// Consider writting a test for this assumption, so that if Apply changes
			// we catch semantic change.
			if err = w.localStorage.Apply(ctx, &storageApi.ApplyRequest{
				Namespace: diff.thisRoot.Namespace,
				RootType:  diff.thisRoot.Type,
				SrcRound:  diff.prevRoot.Version,
				SrcRoot:   diff.prevRoot.Hash,
				DstRound:  diff.thisRoot.Version,
				DstRoot:   diff.thisRoot.Hash,
				WriteLog:  diff.writeLog,
			}); err != nil {
				w.logger.Error("failed to apply storage diff", "err", err)
				w.fetcher.Reject()
				continue
				// TODO error handling has now changed.
			}

			w.logger.Debug("applied", "root", diff.thisRoot)
			w.fetcher.Accept()
			applied = append(applied, diff.thisRoot)

			// The worker expected that two storage roots are always finalized.
			// Maybe it should not.
			if len(applied) < 2 {
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case appliedCh <- applied:
				applied = nil
			}
		}
	})

	// Finalize.
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case roots := <-appliedCh:
				finalized, err := w.finalize(roots)
				if err != nil {
					return fmt.Errorf("failed to finalize: %w", err)
				}
				w.notify(finalized)
			}
		}
	})

	return g.Wait()
}

func (w *Worker) finalize(roots []storageApi.Root) (Finalized, error) {
	err := w.localStorage.NodeDB().Finalize(roots)

	var round uint64
	for _, root := range roots {
		round = root.Version
	}

	switch {
	case err == nil:
		w.logger.Debug("finalized", "round", round)
	case errors.Is(err, storageApi.ErrAlreadyFinalized):
		// This can happen if we are restoring after a roothash migration or if
		// we crashed before updating the sync state.
		w.logger.Warn("already finalized", "round", round)
	default:
		return Finalized{}, fmt.Errorf("failed to finalize (round: %d): %w", round, err)
	}
	return Finalized{round, roots}, nil
}

func (w *Worker) notify(f Finalized) {
	select {
	case w.updates <- f:
	default:
		select {
		case <-w.updates:
		default:
		}
		w.updates <- f
	}
}
