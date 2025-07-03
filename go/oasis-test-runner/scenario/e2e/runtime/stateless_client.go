package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/config"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// StatelessClient is the stateless client scenario.
var StatelessClient scenario.Scenario = newStatelessClientImpl()

type statelessClientImpl struct {
	Scenario
}

func newStatelessClientImpl() scenario.Scenario {
	sc := &statelessClientImpl{
		Scenario: *NewScenario(
			"stateless-client",
			NewTestClient().WithScenario(InsertRemoveEncWithSecretsScenario),
		),
	}
	return sc
}

func (sc *statelessClientImpl) Clone() scenario.Scenario {
	return &statelessClientImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *statelessClientImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	f.StatelessClients = []oasis.StatelessClientFixture{
		{
			RuntimeProvisioner: f.Clients[0].RuntimeProvisioner,
			Runtimes:           []int{1},
			NodeFixture: oasis.NodeFixture{
				NoAutoStart: true,
			},
		},
	}

	return f, nil
}

func (sc *statelessClientImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Prepare trust root for the stateless client.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	blk, err := sc.WaitBlocks(ctx, 5)
	if err != nil {
		return err
	}

	trust := config.TrustConfig{
		Period: time.Hour,
		Height: uint64(blk.Height),
		Hash:   blk.Hash.Hex(),
	}

	client := sc.Net.StatelessClients()[0]
	client.ConfigureConsensusLightClient(trust)

	// Start the stateless client.
	sc.Logger.Info("starting stateless client")

	if err := client.Start(); err != nil {
		return fmt.Errorf("failed to start stateless client: %w", err)
	}
	if err := client.WaitReady(ctx); err != nil {
		return fmt.Errorf("failed to wait for stateless client to be ready: %w", err)
	}

	// Prepare stateless client controller.
	ctrl, err := oasis.NewController(client.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for stateless client: %w", err)
	}

	// Test watching consensus blocks.
	sc.Logger.Info("watching consensus blocks")

	blkCh, blkSub, err := ctrl.Consensus.WatchBlocks(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch consensus blocks: %w", err)
	}
	defer blkSub.Close()

	for range 3 {
		select {
		case blk := <-blkCh:
			sc.Logger.Info("new consensus block", "height", blk.Height)
		case <-time.After(time.Minute):
			return fmt.Errorf("no consensus block")
		}
	}

	// Generate runtime blocks.
	if err := sc.StartTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Test watching consensus blocks.
	sc.Logger.Info("watching runtime blocks")

	rtBlkCh, rtBlkSub, err := ctrl.Roothash.WatchBlocks(ctx, KeyValueRuntimeID)
	if err != nil {
		return fmt.Errorf("failed to watch runtime blocks: %w", err)
	}
	defer rtBlkSub.Close()

	for range 3 {
		select {
		case blk := <-rtBlkCh:
			sc.Logger.Info("new runtime block", "height", blk.Height, "round", blk.Block.Header.Round)
		case <-time.After(time.Minute):
			return fmt.Errorf("no runtime block")
		}
	}

	return sc.WaitTestClientAndCheckLogs()
}
