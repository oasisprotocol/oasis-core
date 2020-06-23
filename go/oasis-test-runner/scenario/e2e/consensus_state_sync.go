package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// ConsensusStateSync is the consensus state sync scenario.
var ConsensusStateSync scenario.Scenario = &consensusStateSyncImpl{
	E2E: *NewE2E("consensus-state-sync"),
}

type consensusStateSyncImpl struct {
	E2E
}

func (sc *consensusStateSyncImpl) Clone() scenario.Scenario {
	return &consensusStateSyncImpl{
		E2E: sc.E2E.Clone(),
	}
}

func (sc *consensusStateSyncImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// Enable checkpoints.
	f.Network.Consensus.Parameters.StateCheckpointInterval = 10
	f.Network.Consensus.Parameters.StateCheckpointNumKept = 100
	f.Network.Consensus.Parameters.StateCheckpointChunkSize = 1024 * 1024
	// Add an extra validator.
	f.Validators = append(f.Validators,
		oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
	)

	return f, nil
}

func (sc *consensusStateSyncImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	sc.Logger.Info("waiting for network to come up")
	ctx := context.Background()
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
		return err
	}

	// Stop one of the validators.
	val := sc.Net.Validators()[2]
	if err := val.Stop(); err != nil {
		return fmt.Errorf("failed to stop validator: %w", err)
	}

	// Let the network run for 50 blocks. This should generate some checkpoints.
	blockCh, blockSub, err := sc.Net.Controller().Consensus.WatchBlocks(ctx)
	if err != nil {
		return err
	}
	defer blockSub.Close()

	sc.Logger.Info("waiting for some blocks")
	var blk *consensus.Block
	for {
		select {
		case blk = <-blockCh:
			if blk.Height < 50 {
				continue
			}
		case <-time.After(30 * time.Second):
			return fmt.Errorf("timed out waiting for blocks")
		}

		break
	}

	sc.Logger.Info("got some blocks, starting the validator back",
		"trust_height", blk.Height,
		"trust_hash", hex.EncodeToString(blk.Hash),
	)

	// Get the TLS public key from the validators.
	var consensusNodes []string
	for _, v := range sc.Net.Validators()[:2] {
		var ctrl *oasis.Controller
		ctrl, err = oasis.NewController(v.SocketPath())
		if err != nil {
			return fmt.Errorf("failed to create controller for validator %s: %w", v.Name, err)
		}

		var status *control.Status
		status, err = ctrl.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to get status for validator %s: %w", v.Name, err)
		}

		if status.Registration.Descriptor == nil {
			return fmt.Errorf("validator %s has not registered", v.Name)
		}
		if len(status.Registration.Descriptor.TLS.Addresses) == 0 {
			return fmt.Errorf("validator %s has no TLS addresses", v.Name)
		}

		var rawAddress []byte
		tlsAddress := status.Registration.Descriptor.TLS.Addresses[0]
		rawAddress, err = tlsAddress.MarshalText()
		if err != nil {
			return fmt.Errorf("failed to marshal TLS address: %w", err)
		}
		consensusNodes = append(consensusNodes, string(rawAddress))
	}

	// Configure state sync for the consensus validator.
	val.SetConsensusStateSync(&oasis.ConsensusStateSyncCfg{
		ConsensusNodes: consensusNodes,
		TrustHeight:    uint64(blk.Height),
		TrustHash:      hex.EncodeToString(blk.Hash),
	})

	if err = val.Start(); err != nil {
		return fmt.Errorf("failed to start validator back: %w", err)
	}

	// Wait for the validator to finish syncing.
	sc.Logger.Info("waiting for the validator to sync")
	valCtrl, err := oasis.NewController(val.SocketPath())
	if err != nil {
		return err
	}
	if err = valCtrl.WaitSync(ctx); err != nil {
		return err
	}

	return nil
}
