package interop

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

// InitializeTestRoothashState must be kept in sync with tests in runtimes/consensus/state/roothash.rs.
func InitializeTestRoothashState(ctx context.Context, mkvs mkvs.Tree) error {
	var runtimeID common.Namespace
	if err := runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000010"); err != nil {
		return err
	}

	state := roothashState.NewMutableState(mkvs)

	if err := state.SetConsensusParameters(ctx, &api.ConsensusParameters{
		MaxPastRootsStored: 100,
	}); err != nil {
		return err
	}

	// Prepare initial runtime state.
	// TODO: fill the rest if needed for interop tests in future.
	runtimeState := &api.RuntimeState{
		Runtime: &registry.Runtime{
			ID: runtimeID,
		},
		Suspended: false,
		GenesisBlock: &block.Block{Header: block.Header{
			Round:     1,
			IORoot:    hash.NewFromBytes([]byte("genesis")),
			StateRoot: hash.NewFromBytes([]byte("genesis")),
		}},
		LastBlock: &block.Block{Header: block.Header{
			Round:     1,
			IORoot:    hash.NewFromBytes([]byte("genesis")),
			StateRoot: hash.NewFromBytes([]byte("genesis")),
		}},
		LastBlockHeight:  1,
		LastNormalRound:  1,
		LastNormalHeight: 1,
	}
	if err := state.SetRuntimeState(ctx, runtimeState); err != nil {
		return err
	}

	// Save some runtime state rounds, so we fill past roots state.
	for i := 0; i < 10; i++ {
		runtimeState.LastBlock = &block.Block{Header: block.Header{
			Round:     uint64(i + 1),
			IORoot:    hash.NewFromBytes([]byte(fmt.Sprintf("io %d", i+1))),
			StateRoot: hash.NewFromBytes([]byte(fmt.Sprintf("state %d", i+1))),
		}}
		runtimeState.LastNormalRound = uint64(i + 1)
		runtimeState.LastBlockHeight = int64(i * 10)
		runtimeState.LastNormalHeight = int64(i * 10)

		if err := state.SetRuntimeState(ctx, runtimeState); err != nil {
			return err
		}
	}

	return nil
}
