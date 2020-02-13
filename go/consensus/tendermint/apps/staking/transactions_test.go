package staking

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func TestIsTransferPermitted(t *testing.T) {
	for _, tt := range []struct {
		msg       string
		params    *staking.ConsensusParameters
		fromID    signature.PublicKey
		from      *staking.Account
		epoch     epochtime.EpochTime
		permitted bool
	}{
		{
			"no disablement",
			&staking.ConsensusParameters{},
			signature.PublicKey{},
			&staking.Account{},
			0,
			true,
		},
		{
			"all disabled",
			&staking.ConsensusParameters{
				DisableTransfers: true,
			},
			signature.PublicKey{},
			&staking.Account{},
			0,
			false,
		},
		{
			"not whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[signature.PublicKey]bool{
					signature.PublicKey{1}: true,
				},
			},
			signature.PublicKey{},
			&staking.Account{},
			0,
			false,
		},
		{
			"whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[signature.PublicKey]bool{
					signature.PublicKey{}: true,
				},
			},
			signature.PublicKey{},
			&staking.Account{},
			0,
			true,
		},
		{
			"before allowed",
			&staking.ConsensusParameters{},
			signature.PublicKey{},
			&staking.Account{
				General: staking.GeneralAccount{
					TransfersNotBefore: 1,
				},
			},
			0,
			false,
		},
		{
			"after allowed",
			&staking.ConsensusParameters{},
			signature.PublicKey{},
			&staking.Account{},
			1,
			true,
		},
		{
			"whitelisted before allowed ",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[signature.PublicKey]bool{
					signature.PublicKey{}: true,
				},
			},
			signature.PublicKey{},
			&staking.Account{
				General: staking.GeneralAccount{
					TransfersNotBefore: 1,
				},
			},
			0,
			false,
		},
	} {
		require.Equal(t, tt.permitted, isTransferPermitted(tt.params, tt.fromID, tt.from, tt.epoch), tt.msg)
	}
}
