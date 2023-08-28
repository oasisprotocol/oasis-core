package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
)

// StartNetworkAndWaitForClientSync starts the network and waits for the client node to sync.
func (sc *Scenario) StartNetworkAndWaitForClientSync(ctx context.Context) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	return sc.WaitForClientSync(ctx)
}

// StartNetworkAndTestClient starts the network and the runtime test client.
func (sc *Scenario) StartNetworkAndTestClient(ctx context.Context, childEnv *env.Env) error {
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return fmt.Errorf("failed to initialize network: %w", err)
	}

	return sc.StartTestClient(ctx, childEnv)
}

// StartTestClient initializes and starts the runtime test client.
func (sc *Scenario) StartTestClient(ctx context.Context, childEnv *env.Env) error {
	if err := sc.TestClient.Init(sc); err != nil {
		return fmt.Errorf("failed to initialize test client: %w", err)
	}

	if err := sc.TestClient.Start(ctx, childEnv); err != nil {
		return fmt.Errorf("failed to start test client: %w", err)
	}

	return nil
}

// RunTestClientAndCheckLogs initializes and starts the runtime test client,
// waits for the runtime test client to finish its work and then verifies the logs.
func (sc *Scenario) RunTestClientAndCheckLogs(ctx context.Context, childEnv *env.Env) error {
	if err := sc.StartTestClient(ctx, childEnv); err != nil {
		return err
	}

	return sc.WaitTestClientAndCheckLogs()
}

// WaitNodesSynced waits for all the nodes to sync.
func (sc *Scenario) WaitNodesSynced(ctx context.Context) error {
	checkSynced := func(n *oasis.Node) error {
		c, err := oasis.NewController(n.SocketPath())
		if err != nil {
			return fmt.Errorf("failed to create node controller: %w", err)
		}
		defer c.Close()

		if err = c.WaitSync(ctx); err != nil {
			return fmt.Errorf("failed to wait for node to sync: %w", err)
		}
		return nil
	}

	sc.Logger.Info("waiting for all nodes to be synced")

	for _, n := range sc.Net.Validators() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.Net.Keymanagers() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.Net.ComputeWorkers() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.Net.Clients() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}

	sc.Logger.Info("nodes synced")
	return nil
}

// WaitForClientSync waits for the first client to sync.
func (sc *Scenario) WaitForClientSync(ctx context.Context) error {
	clients := sc.Net.Clients()
	if len(clients) == 0 {
		return fmt.Errorf("scenario/e2e: network has no client nodes")
	}

	sc.Logger.Info("ensuring client node is synced")
	ctrl, err := oasis.NewController(clients[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for client: %w", err)
	}
	if err = ctrl.WaitSync(ctx); err != nil {
		return fmt.Errorf("client-0 failed to sync: %w", err)
	}

	return nil
}

// WaitTestClient waits for the runtime test client to finish its work.
func (sc *Scenario) WaitTestClient() error {
	sc.Logger.Info("waiting for test client to exit")
	return sc.TestClient.Wait()
}

// WaitTestClientAndCheckLogs waits for the runtime test client to finish its work
// and then verifies the logs.
func (sc *Scenario) WaitTestClientAndCheckLogs() error {
	if err := sc.WaitTestClient(); err != nil {
		return err
	}
	return sc.checkTestClientLogs()
}

func (sc *Scenario) checkTestClientLogs() error {
	sc.Logger.Info("checking test client logs")

	// Wait for logs to be fully processed before checking them. When
	// the client exits very quickly the log watchers may not have
	// processed the relevant logs yet.
	//
	// TODO: Find a better way to synchronize log watchers.
	time.Sleep(1 * time.Second)

	return sc.Net.CheckLogWatchers()
}

// StartKeymanagers starts the specified key manager nodes.
func (sc *Scenario) StartKeymanagers(idxs []int) error {
	sc.Logger.Info("starting the key managers", "ids", fmt.Sprintf("%+v", idxs))

	kms := sc.Net.Keymanagers()
	for _, idx := range idxs {
		if err := kms[idx].Start(); err != nil {
			return err
		}
	}
	return nil
}

// StopKeymanagers stops the specified key manager nodes.
func (sc *Scenario) StopKeymanagers(idxs []int) error {
	sc.Logger.Info("stopping the key managers", "ids", fmt.Sprintf("%+v", idxs))

	kms := sc.Net.Keymanagers()
	for _, idx := range idxs {
		if err := kms[idx].Stop(); err != nil {
			return err
		}
	}
	return nil
}

// RestartKeymanagers restarts the specified key manager nodes.
func (sc *Scenario) RestartKeymanagers(ctx context.Context, idxs []int) error {
	sc.Logger.Info("restarting the key managers", "ids", fmt.Sprintf("%+v", idxs))

	kms := sc.Net.Keymanagers()
	for _, idx := range idxs {
		if err := kms[idx].Restart(ctx); err != nil {
			return err
		}
	}
	return nil
}

// WaitKeymanagers waits for the specified key manager nodes to become ready.
func (sc *Scenario) WaitKeymanagers(ctx context.Context, idxs []int) error {
	sc.Logger.Info("waiting for the key managers to become ready", "ids", fmt.Sprintf("%+v", idxs))

	kms := sc.Net.Keymanagers()
	for _, idx := range idxs {
		kmCtrl, err := oasis.NewController(kms[idx].SocketPath())
		if err != nil {
			return err
		}
		if err = kmCtrl.WaitReady(ctx); err != nil {
			return err
		}
	}
	return nil
}

// StartAndWaitKeymanagers starts the specified key manager nodes and waits
// for them to become ready.
func (sc *Scenario) StartAndWaitKeymanagers(ctx context.Context, idxs []int) error {
	if err := sc.StartKeymanagers(idxs); err != nil {
		return err
	}
	return sc.WaitKeymanagers(ctx, idxs)
}

// RestartAndWaitKeymanagers restarts the specified key manager nodes and waits
// for them to become ready.
func (sc *Scenario) RestartAndWaitKeymanagers(ctx context.Context, idxs []int) error {
	if err := sc.RestartKeymanagers(ctx, idxs); err != nil {
		return err
	}
	return sc.WaitKeymanagers(ctx, idxs)
}
