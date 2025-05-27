package light

import (
	"fmt"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// EncodeLightBlock creates a new consensus light bock from a CometBFT light block.
func EncodeLightBlock(clb *cmttypes.LightBlock) (*consensus.LightBlock, error) {
	plb, err := clb.ToProto()
	if err != nil {
		return nil, fmt.Errorf("failed to convert light block: %w", err)
	}
	meta, err := plb.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal light block: %w", err)
	}

	return &consensus.LightBlock{
		Height: clb.Height,
		Meta:   meta,
	}, nil
}

// DecodeLightBlock creates a new CometBFT light block from a consensus light bock.
func DecodeLightBlock(lb *consensus.LightBlock) (*cmttypes.LightBlock, error) {
	var plb cmtproto.LightBlock
	if err := plb.Unmarshal(lb.Meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal light block: %w", err)
	}
	clb, err := cmttypes.LightBlockFromProto(&plb)
	if err != nil {
		return nil, fmt.Errorf("failed to convert light block: %w", err)
	}
	return clb, nil
}
