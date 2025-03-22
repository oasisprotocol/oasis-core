package light

import (
	"fmt"

	cmttypes "github.com/cometbft/cometbft/types"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// NewLightBlock creates a new consensus light bock from a CometBFT light block.
func NewLightBlock(clb *cmttypes.LightBlock) (*consensus.LightBlock, error) {
	plb, err := clb.ToProto()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal light block: %w", err)
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
