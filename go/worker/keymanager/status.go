package keymanager

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
)

// GetStatus returns the key manager worker status.
func (w *Worker) GetStatus(ctx context.Context) (*api.Status, error) {
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

	ps := make([]peer.ID, 0, len(w.privatePeers))
	for p := range w.privatePeers {
		ps = append(ps, p)
	}

	w.RLock()
	defer w.RUnlock()

	rts := make([]common.Namespace, 0, len(w.clientRuntimes))
	for rt := range w.clientRuntimes {
		rts = append(rts, rt)
	}

	al := make([]api.RuntimeAccessList, 0, len(w.accessListByRuntime))
	for rt, ps := range w.accessListByRuntime {
		ral := api.RuntimeAccessList{
			RuntimeID: rt,
			Peers:     ps,
		}
		al = append(al, ral)
	}

	var pc []byte
	if w.enclaveStatus != nil {
		pc = w.enclaveStatus.InitResponse.PolicyChecksum
	}

	gs := w.globalStatus
	ws := api.WorkerStatus{
		Status:           ss,
		MayGenerate:      w.mayGenerate,
		ClientRuntimes:   rts,
		AccessList:       al,
		PrivatePeers:     ps,
		Policy:           w.policy,
		PolicyChecksum:   pc,
		MasterSecrets:    w.masterSecretStats,
		EphemeralSecrets: w.ephemeralSecretStats,
	}

	return &api.Status{
		GlobalStatus: gs,
		WorkerStatus: ws,
	}, nil
}
