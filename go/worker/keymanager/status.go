package keymanager

import (
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
)

// GetStatus returns the key manager worker status.
func (w *Worker) GetStatus() (*api.Status, error) {
	var initialized, stopped bool
	select {
	case <-w.Initialized():
		initialized = true
	default:
	}
	select {
	case <-w.Quit():
		stopped = true
	default:
	}

	var ss api.StatusState
	switch {
	case !w.enabled:
		ss = api.StatusStateDisabled
	case stopped:
		ss = api.StatusStateStopped
	case initialized:
		ss = api.StatusStateReady
	default:
		ss = api.StatusStateStarting
	}

	av, _ := w.GetHostedRuntimeActiveVersion()
	al := w.accessList.RuntimeAccessLists()

	var rts []common.Namespace
	if w.kmRuntimeWatcher != nil {
		rts = w.kmRuntimeWatcher.Runtimes()
	}

	var s *api.SecretsStatus
	if w.secretsWorker != nil {
		s = w.secretsWorker.GetStatus()
	}

	w.RLock()
	defer w.RUnlock()

	return &api.Status{
		Status:         ss,
		ActiveVersion:  av,
		RuntimeID:      &w.runtimeID,
		ClientRuntimes: rts,
		AccessList:     al,
		Secrets:        s,
	}, nil
}
