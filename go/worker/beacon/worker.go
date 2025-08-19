// Package beacon implements the random beacon worker.
package beacon

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const workerName = "worker/beacon"

type Worker struct {
	vrf *vrfWorker

	ctx context.Context

	identity  *identity.Identity
	consensus consensus.Service

	quitCh chan struct{}
}

func (w *Worker) Start() error {
	if w.vrf != nil {
		if err := w.vrf.Start(); err != nil {
			return fmt.Errorf("worker/beacon: failed to start VRF worker: %w", err)
		}
	}

	return nil
}

func (w *Worker) Stop() {
	if w.vrf != nil {
		w.vrf.Stop()
		<-w.vrf.Quit()
	}
	close(w.quitCh)
}

func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

func (w *Worker) Cleanup() {
	if w.vrf != nil {
		w.vrf.Cleanup()
	}
}

func (w *Worker) Name() string {
	return "beacon worker"
}

// New creates a new worker instance.
func New(
	identity *identity.Identity,
	consensus consensus.Service,
	registrationWorker *registration.Worker,
) (*Worker, error) {
	w := &Worker{
		ctx:       context.Background(),
		identity:  identity,
		consensus: consensus,
		quitCh:    make(chan struct{}),
	}

	logger := logging.GetLogger(workerName)
	if registrationWorker.WillNeverRegister() {
		// Some node configurations never register, and that's ok.
		logger.Info("registration worker disabled, also disabling beacon worker")
		return w, nil
	}

	vrf, err := newVRF(w)
	if err != nil {
		logger.Error("failed to initialize VRF worker",
			"err", err,
		)
		return nil, err
	}
	w.vrf = vrf

	return w, nil
}
