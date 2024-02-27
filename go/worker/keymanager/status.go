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

	var status api.StatusState
	switch {
	case !w.enabled:
		status = api.StatusStateDisabled
	case stopped:
		status = api.StatusStateStopped
	case initialized:
		status = api.StatusStateReady
	default:
		status = api.StatusStateStarting
	}

	activeVersion, _ := w.GetHostedRuntimeActiveVersion()
	accessList := w.accessList.RuntimeAccessLists()

	var runtimeClients []common.Namespace
	if w.kmRuntimeWatcher != nil {
		runtimeClients = w.kmRuntimeWatcher.Runtimes()
	}

	var secrets *api.SecretsStatus
	if w.secretsWorker != nil {
		secrets = w.secretsWorker.GetStatus()
	}

	var churp api.ChurpStatus
	if w.churpWorker != nil {
		churp = w.churpWorker.GetStatus()
	}

	w.RLock()
	defer w.RUnlock()

	return &api.Status{
		Status:         status,
		ActiveVersion:  activeVersion,
		RuntimeID:      &w.runtimeID,
		ClientRuntimes: runtimeClients,
		AccessList:     accessList,
		Secrets:        secrets,
		Churp:          churp,
	}, nil
}
