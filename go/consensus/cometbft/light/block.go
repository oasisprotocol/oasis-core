package light

import (
	"fmt"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// EncodeLightBlock creates a new consensus light bock from a CometBFT light block.
//
// The height must be provided explicitly, as the light block's header may be empty.
func EncodeLightBlock(lb *cmttypes.LightBlock, height int64) (*consensus.LightBlock, error) {
	plb, err := lightBlockToProto(lb)
	if err != nil {
		return nil, fmt.Errorf("failed to convert light block: %w", err)
	}

	meta, err := plb.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal light block: %w", err)
	}

	return &consensus.LightBlock{
		Height: height,
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

// EncodeValidators creates a new consensus validator set from a CometBFT validator set.
func EncodeValidators(validators *cmttypes.ValidatorSet, height int64) (*consensus.Validators, error) {
	lb := cmttypes.LightBlock{
		ValidatorSet: validators,
	}

	plb, err := lightBlockToProto(&lb)
	if err != nil {
		return nil, err
	}

	meta, err := plb.ValidatorSet.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal validators: %w", err)
	}

	return &consensus.Validators{
		Height: height,
		Meta:   meta,
	}, nil
}

// DecodeValidators creates a new CometBFT validator set from a consensus validator set.
func DecodeValidators(validators *consensus.Validators) (*cmttypes.ValidatorSet, error) {
	var pvs cmtproto.ValidatorSet
	if err := pvs.Unmarshal(validators.Meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validators: %w", err)
	}

	vs, err := cmttypes.ValidatorSetFromProto(&pvs)
	if err != nil {
		return nil, fmt.Errorf("failed to convert validators: %w", err)
	}

	return vs, nil
}

func lightBlockToProto(lb *cmttypes.LightBlock) (*cmtproto.LightBlock, error) {
	plb, err := lb.ToProto()
	if err != nil {
		return nil, err
	}

	if plb.ValidatorSet != nil {
		// ToProto sets the TotalVotingPower to 0, but the rust side FromProto requires it.
		// https://github.com/tendermint/tendermint/blob/41c176ccc6a75d25631d0f891efb2e19a33329dc/types/validator_set.go#L949-L951
		// https://github.com/informalsystems/tendermint-rs/blob/c70f6eea9ccd1f41c0a608c5285b6af98b66c9fe/tendermint/src/validator.rs#L38-L45
		plb.ValidatorSet.TotalVotingPower = lb.ValidatorSet.TotalVotingPower()
	}

	return plb, nil
}
