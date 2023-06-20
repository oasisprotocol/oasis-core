package tests

import (
	"os"
	"path/filepath"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// MakeConsensusEquivocationEvidence creates consensus evidence of equivocation.
func MakeConsensusEquivocationEvidence(ident *identity.Identity, blk *consensus.Block, genesis *genesis.Document, totalVotingPower, votingPower int64) (*consensus.Evidence, error) {
	// Create empty directory for private validator metadata.
	tmpDir, err := os.MkdirTemp("", "oasis-slash-test")
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

	// Generate fake CometBFT-specific double-signing evidence for the
	// current node (as this node is the only validator during tests).
	//
	// This means that the vote is for the same height/round/step but for
	// different block IDs.
	blockID1 := cmttypes.BlockID{
		Hash: []byte("blockhashblockhashblockhashbloc1"),
		PartSetHeader: cmttypes.PartSetHeader{
			Total: 1000,
			Hash:  []byte("partshashpartshashpartshashpart1"),
		},
	}
	blockID2 := cmttypes.BlockID{
		Hash: []byte("blockhashblockhashblockhashbloc1"),
		PartSetHeader: cmttypes.PartSetHeader{
			Total: 1000,
			Hash:  []byte("partshashpartshashpartshashpart2"),
		},
	}
	chainID := api.CometBFTChainID(genesis.ChainContext())

	ev := &cmttypes.DuplicateVoteEvidence{
		Timestamp:        blk.Time,
		TotalVotingPower: totalVotingPower,
		ValidatorPower:   votingPower,
		VoteA:            makeVote(pv1, chainID, 0, blk.Height, 2, 1, blockID1, blk.Time),
		VoteB:            makeVote(pv2, chainID, 0, blk.Height, 2, 1, blockID2, blk.Time),
	}

	proto, err := cmttypes.EvidenceToProto(ev)
	if err != nil {
		return nil, err
	}
	meta, err := proto.Marshal()
	if err != nil {
		return nil, err
	}

	return &consensus.Evidence{Meta: meta}, nil
}

// makeVote copied from CometBFT test suite.
func makeVote(val cmttypes.PrivValidator, chainID string, valIndex int32, height int64, round int32, step int, blockID cmttypes.BlockID, ts time.Time) *cmttypes.Vote {
	pk, err := val.GetPubKey()
	if err != nil {
		panic(err)
	}
	addr := pk.Address()
	v := &cmttypes.Vote{
		ValidatorAddress: addr,
		ValidatorIndex:   valIndex,
		Height:           height,
		Round:            round,
		Type:             cmtproto.SignedMsgType(step),
		BlockID:          blockID,
		Timestamp:        ts,
	}
	vpb := v.ToProto()
	err = val.SignVote(chainID, vpb)
	if err != nil {
		panic(err)
	}
	v.Signature = vpb.Signature
	return v
}
