package tests

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// MakeConsensusEquivocationEvidence creates consensus evidence of equivocation.
func MakeConsensusEquivocationEvidence(ident *identity.Identity, blk *consensus.Block, genesis *genesis.Document, totalVotingPower, votingPower int64) (*consensus.Evidence, error) {
	// Create empty directory for private validator metadata.
	tmpDir, err := ioutil.TempDir("", "oasis-slash-test")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	// Create two private validators that share the same key as otherwise
	// double signing will fail.
	pv1Path := filepath.Join(tmpDir, "pv1")
	err = os.Mkdir(pv1Path, 0o700)
	if err != nil {
		return nil, err
	}
	pv1, err := tmcrypto.LoadOrGeneratePrivVal(pv1Path, ident.ConsensusSigner)
	if err != nil {
		return nil, err
	}
	pv2Path := filepath.Join(tmpDir, "pv2")
	err = os.Mkdir(pv2Path, 0o700)
	if err != nil {
		return nil, err
	}
	pv2, err := tmcrypto.LoadOrGeneratePrivVal(pv2Path, ident.ConsensusSigner)
	if err != nil {
		return nil, err
	}

	// Generate fake Tendermint-specific double-signing evidence for the
	// current node (as this node is the only validator during tests).
	//
	// This means that the vote is for the same height/round/step but for
	// different block IDs.
	blockID1 := tmtypes.BlockID{
		Hash: []byte("blockhashblockhashblockhashbloc1"),
		PartSetHeader: tmtypes.PartSetHeader{
			Total: 1000,
			Hash:  []byte("partshashpartshashpartshashpart1"),
		},
	}
	blockID2 := tmtypes.BlockID{
		Hash: []byte("blockhashblockhashblockhashbloc1"),
		PartSetHeader: tmtypes.PartSetHeader{
			Total: 1000,
			Hash:  []byte("partshashpartshashpartshashpart2"),
		},
	}
	chainID := genesis.ChainContext()[:tmtypes.MaxChainIDLen]

	ev := &tmtypes.DuplicateVoteEvidence{
		Timestamp:        blk.Time,
		TotalVotingPower: totalVotingPower,
		ValidatorPower:   votingPower,
		VoteA:            makeVote(pv1, chainID, 0, blk.Height, 2, 1, blockID1, blk.Time),
		VoteB:            makeVote(pv2, chainID, 0, blk.Height, 2, 1, blockID2, blk.Time),
	}

	proto, err := tmtypes.EvidenceToProto(ev)
	if err != nil {
		return nil, err
	}
	meta, err := proto.Marshal()
	if err != nil {
		return nil, err
	}

	return &consensus.Evidence{Meta: meta}, nil
}

// makeVote copied from Tendermint test suite.
func makeVote(val tmtypes.PrivValidator, chainID string, valIndex int32, height int64, round int32, step int, blockID tmtypes.BlockID, ts time.Time) *tmtypes.Vote {
	pk, err := val.GetPubKey(context.Background())
	if err != nil {
		panic(err)
	}
	addr := pk.Address()
	v := &tmtypes.Vote{
		ValidatorAddress: addr,
		ValidatorIndex:   valIndex,
		Height:           height,
		Round:            round,
		Type:             tmproto.SignedMsgType(step),
		BlockID:          blockID,
		Timestamp:        ts,
	}
	vpb := v.ToProto()
	err = val.SignVote(context.Background(), chainID, vpb)
	if err != nil {
		panic(err)
	}
	v.Signature = vpb.Signature
	return v
}
