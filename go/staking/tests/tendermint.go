package tests

// NOTE: This file contains Tendermint-specific tests.

import (
	"context"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/staking/api"
	tmcrypto "github.com/oasislabs/oasis-core/go/tendermint/crypto"
)

func testSlashDoubleSigning(
	t *testing.T,
	backend api.Backend,
	timeSource epochtime.SetableBackend,
	ident *identity.Identity,
	ent *entity.Entity,
) {
	require := require.New(t)

	// Delegate some stake to the validator so we can check if slashing works.
	srcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "AccountInfo")

	escrowCh, escrowSub := backend.WatchEscrows()
	defer escrowSub.Close()

	escrow := &api.Escrow{
		Nonce:   srcAcc.General.Nonce,
		Account: ent.ID,
		Tokens:  QtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignEscrow(srcSigner, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")

	select {
	case rawEv := <-escrowCh:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(ent.ID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	// Create empty directory for private validator metadata.
	tmpDir, err := ioutil.TempDir("", "oasis-slash-test")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(tmpDir)

	// Create two private validators that share the same key as otherwise
	// double signing will fail.
	pv1Path := filepath.Join(tmpDir, "pv1")
	err = os.Mkdir(pv1Path, 0700)
	require.NoError(err, "Mkdir")
	pv1, err := tmcrypto.LoadOrGeneratePrivVal(pv1Path, ident.ConsensusSigner)
	require.NoError(err, "LoadOrGeneratePrivVal")
	pv2Path := filepath.Join(tmpDir, "pv2")
	err = os.Mkdir(pv2Path, 0700)
	require.NoError(err, "Mkdir")
	pv2, err := tmcrypto.LoadOrGeneratePrivVal(pv2Path, ident.ConsensusSigner)
	require.NoError(err, "LoadOrGeneratePrivVal")

	// Generate fake Tendermint-specific double-signing evidence for the
	// current node (as this node is the only validator during tests).
	//
	// This means that the vote is for the same height/round/step but for
	// different block IDs.
	blockID1 := tmtypes.BlockID{
		Hash: []byte("blockhashblockhashblockhashbloc1"),
		PartsHeader: tmtypes.PartSetHeader{
			Total: 1000,
			Hash:  []byte("partshashpartshashpartshashpart1"),
		},
	}
	blockID2 := tmtypes.BlockID{
		Hash: []byte("blockhashblockhashblockhashbloc1"),
		PartsHeader: tmtypes.PartSetHeader{
			Total: 1000,
			Hash:  []byte("partshashpartshashpartshashpart2"),
		},
	}
	ev := &tmtypes.DuplicateVoteEvidence{
		PubKey: pv1.GetPubKey(),
		// NOTE: ChainID must match the unit test genesis block.
		VoteA: makeVote(pv1, "oasis-test-chain", 0, 1, 2, 1, blockID1),
		VoteB: makeVote(pv2, "oasis-test-chain", 0, 1, 2, 1, blockID2),
	}

	// Subscribe to slash events.
	slashCh, slashSub := backend.WatchEscrows()
	defer slashSub.Close()

	// Broadcast evidence.
	err = backend.SubmitEvidence(context.Background(), api.NewConsensusEvidence(ev))
	require.NoError(err, "SubmitEvidence")

	// Wait for the node to get slashed.
WaitLoop:
	for {
		select {
		case ev := <-slashCh:
			if e, ok := ev.(*api.TakeEscrowEvent); ok {
				require.Equal(ent.ID, e.Owner, "TakeEscrowEvent - owner must be entity")
				// All tokens must be slashed as defined in debugGenesisState.
				require.Equal(escrow.Tokens, e.Tokens, "TakeEscrowEvent - all tokens slashed")
				break WaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive slash event")
		}
	}

	// TODO: Make sure the node is frozen.
}

// makeVote copied from Tendermint test suite.
func makeVote(val tmtypes.PrivValidator, chainID string, valIndex int, height int64, round, step int, blockID tmtypes.BlockID) *tmtypes.Vote {
	addr := val.GetPubKey().Address()
	v := &tmtypes.Vote{
		ValidatorAddress: addr,
		ValidatorIndex:   valIndex,
		Height:           height,
		Round:            round,
		Type:             tmtypes.SignedMsgType(step),
		BlockID:          blockID,
	}
	err := val.SignVote(chainID, v)
	if err != nil {
		panic(err)
	}
	return v
}
