package tests

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/identity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	tmcrypto "github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	genesisTestHelpers "github.com/oasislabs/oasis-core/go/genesis/tests/helpers"
)

// MakeDoubleSignEvidence creates consensus evidence of double signing.
func MakeDoubleSignEvidence(t *testing.T, ident *identity.Identity) consensus.Evidence {
	require := require.New(t)

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
		VoteA: makeVote(pv1, genesisTestHelpers.TestChainID, 0, 1, 2, 1, blockID1),
		VoteB: makeVote(pv2, genesisTestHelpers.TestChainID, 0, 1, 2, 1, blockID2),
	}
	return consensus.NewConsensusEvidence(ev)
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
