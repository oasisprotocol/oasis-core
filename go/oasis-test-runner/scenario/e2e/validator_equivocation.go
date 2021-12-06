package e2e

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"time"

	tmstore "github.com/tendermint/tendermint/uninternal"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmBadger "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db/badger"
	tendermintTests "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/tests"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// ValidatorEquivocation is the validator equivocation scenario.
var ValidatorEquivocation scenario.Scenario = &validatorEquivocationImpl{
	E2E: *NewE2E("validator-equivocation"),
}

type validatorEquivocationImpl struct {
	E2E
}

func (sc *validatorEquivocationImpl) Clone() scenario.Scenario {
	return &validatorEquivocationImpl{
		E2E: sc.E2E.Clone(),
	}
}

func (sc *validatorEquivocationImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			Slashing: map[staking.SlashReason]staking.Slash{
				staking.SlashConsensusEquivocation: {
					Amount:         *quantity.NewFromUint64(math.MaxInt64),
					FreezeInterval: 1,
				},
			},
		},
		TotalSupply: *quantity.NewFromUint64(1000),
		Ledger: map[staking.Address]*staking.Account{
			TestEntityAccount: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(1000),
				},
			},
		},
	}

	// Mock epoch for testing the freeze interval.
	f.Network.SetMockEpoch()
	f.Network.SetInsecureBeacon()
	f.Network.Beacon.InsecureParameters = &api.InsecureParameters{
		// Since mock epochtime is used, this interval is only relevant for computing
		// the max age of consensus evidence. Make it big enough so that we can submit
		// equivocation evidence for block 1.
		Interval: 1000,
	}

	// Add an extra validator.
	f.Validators = append(f.Validators,
		oasis.ValidatorFixture{
			Entity: 1,
		},
	)

	return f, nil
}

func (sc *validatorEquivocationImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	if err := sc.Net.Start(); err != nil {
		return err
	}

	ctrl := sc.Net.Controller()

	sc.Logger.Info("waiting for network to come up")
	ctx := context.Background()
	if err := ctrl.WaitNodesRegistered(ctx, len(sc.Net.Validators())); err != nil {
		return err
	}

	// Wait some blocks.
	// Let the network run for 50 blocks. This should generate some checkpoints.
	blockCh, blockSub, err := ctrl.Consensus.WatchBlocks(ctx)
	if err != nil {
		return err
	}
	defer blockSub.Close()

	sc.Logger.Info("waiting for some blocks")
	for {
		select {
		case blk := <-blockCh:
			if blk.Height < 50 {
				continue
			}
		case <-time.After(30 * time.Second):
			return fmt.Errorf("timed out waiting for blocks")
		}

		break
	}

	// Load genesis.
	fp, err := genesisFile.NewFileProvider(sc.Net.GenesisPath())
	if err != nil {
		return fmt.Errorf("failed to instantiate genesis document file provider: %w", err)
	}
	doc, err := fp.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis document: %w", err)
	}

	// Load first block.
	blk, err := ctrl.Consensus.GetBlock(ctx, 1)
	if err != nil {
		return fmt.Errorf("failed to get block 1: %w", err)
	}

	// Load validator and its entity.
	ent := sc.Net.Entities()[1]
	entAddr := staking.NewAddress(ent.ID())
	validator := sc.Net.Validators()[len(sc.Net.Validators())-1]
	identity, err := validator.LoadIdentity()
	if err != nil {
		return err
	}

	// Stop validator and load tendermint block from the DB.
	// XXX: for constructing the equivocation evidence we need nanosecond precision
	// timestemp of the block, as that is what tendermint uses for verifying the evidence.
	// oasis-core CBOR encoding uses second precision timestamps, therefore block obtained
	// via `ctrl.Consensus.GetBlock(...)` will have an invalid timestamp.
	sc.Logger.Info("stopping validator")
	if err = validator.Stop(); err != nil {
		return fmt.Errorf("stopping validator: %w", err)
	}
	tmDb, err := tmBadger.New(filepath.Join(validator.DataDir(), "tendermint/data/blockstore.badger.db"), true)
	if err != nil {
		return fmt.Errorf("tendermint badger db: %w", err)
	}
	tmBlkStore := tmstore.NewBlockStore(tmDb)
	tmBlk := tmBlkStore.LoadBlock(1)
	if tmBlk == nil {
		return fmt.Errorf("loading tendermint block failed")
	}
	// Fix block time to nanosecond precision time.
	blk.Time = tmBlk.Time

	// Escrow some to the entity.
	sc.Logger.Info("escrowing to validator entity")
	_, testEntitySigner, _ := entity.TestEntity()
	tx := staking.NewAddEscrowTx(0, &transaction.Fee{Gas: 1000}, &staking.Escrow{Account: entAddr, Amount: mustInitQuantity(100)})
	sigTx, err := transaction.Sign(testEntitySigner, tx)
	if err != nil {
		return fmt.Errorf("failed to sign escrow tx: %w", err)
	}
	if err = ctrl.Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("failed to submit escrow tx: %w", err)
	}

	// Watch staking events.
	ch, sub, err := ctrl.Staking.WatchEvents(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch staking events: %w", err)
	}
	defer sub.Close()

	sc.Logger.Info("submitting equivocation evidence")

	// Prepare and submit equivocation evidence.
	evidence, err := tendermintTests.MakeConsensusEquivocationEvidence(identity, blk, doc, 4, 1)
	if err != nil {
		return fmt.Errorf("failed to make consensus equivocation evidence: %w", err)
	}
	if err = ctrl.Consensus.SubmitEvidence(ctx, evidence); err != nil {
		return fmt.Errorf("failed to submit equivocation evidence: %w", err)
	}

	entAcc, err := ctrl.Staking.Account(ctx, &staking.OwnerQuery{Height: consensusAPI.HeightLatest, Owner: entAddr})
	if err != nil {
		return err
	}

	sc.Logger.Info("waiting for node to get slashed")
	// Wait for the node to get slashed.
WaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.Escrow == nil {
				continue
			}
			if ev.Escrow.Take == nil {
				continue
			}
			e := ev.Escrow.Take

			if entAddr != e.Owner {
				return fmt.Errorf("TakeEscrowEvent - owner must be entity's address, got: %v", e.Owner)
			}
			// All stake must be slashed as defined in genesis.
			if entAcc.Escrow.Active.Balance.Cmp(&e.Amount) != 0 {
				return fmt.Errorf("TakeEscrowEvent - all stake slashed should be slashed: remaining: %v", e.Amount)
			}
			sc.Logger.Info("expected slashing event received")
			break WaitLoop
		case <-time.After(10 * time.Second):
			return fmt.Errorf("failed to receive slash event")
		}
	}

	// Make sure the node is frozen.
	nodeStatus, err := ctrl.Consensus.Registry().GetNodeStatus(ctx, &registry.IDQuery{ID: identity.NodeSigner.Public(), Height: consensusAPI.HeightLatest})
	if err != nil {
		return fmt.Errorf("GetNodeStatus: %w", err)
	}
	if nodeStatus.ExpirationProcessed {
		return fmt.Errorf("ExpirationProcessed should be false")
	}
	if !nodeStatus.IsFrozen() {
		return fmt.Errorf("IsFrozen() should return true")
	}

	// Make sure node cannot be unfrozen.
	tx = registry.NewUnfreezeNodeTx(0, &transaction.Fee{Gas: 2000}, &registry.UnfreezeNode{
		NodeID: identity.NodeSigner.Public(),
	})
	sigTx, err = transaction.Sign(ent.Signer(), tx)
	if err != nil {
		return fmt.Errorf("failed to sign unfreeze: %w", err)
	}
	err = ctrl.Consensus.SubmitTx(ctx, sigTx)
	if !errors.Is(err, registry.ErrNodeCannotBeUnfrozen) {
		return fmt.Errorf("unfreezing the node should fail")
	}

	if err = ctrl.SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("SetEpoch: %w", err)
	}

	// Node can be unfrozen now.
	tx = registry.NewUnfreezeNodeTx(1, &transaction.Fee{Gas: 2000}, &registry.UnfreezeNode{
		NodeID: identity.NodeSigner.Public(),
	})

	sigTx, err = transaction.Sign(ent.Signer(), tx)
	if err != nil {
		return fmt.Errorf("failed to sign unfreeze: %w", err)
	}
	if err = ctrl.Consensus.SubmitTx(ctx, sigTx); err != nil {
		return fmt.Errorf("unfreezing node: %w", err)
	}

	return nil
}
