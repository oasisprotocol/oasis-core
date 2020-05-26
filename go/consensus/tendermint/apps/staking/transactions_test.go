package staking

import (
	"testing"

	"github.com/stretchr/testify/require"

	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestIsTransferPermitted(t *testing.T) {
	for _, tt := range []struct {
		msg       string
		params    *staking.ConsensusParameters
		fromAddr  staking.Address
		permitted bool
	}{
		{
			"no disablement",
			&staking.ConsensusParameters{},
			staking.Address{},
			true,
		},
		{
			"all disabled",
			&staking.ConsensusParameters{
				DisableTransfers: true,
			},
			staking.Address{},
			false,
		},
		{
			"not whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[staking.Address]bool{
					staking.Address{1}: true,
				},
			},
			staking.Address{},
			false,
		},
		{
			"whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[staking.Address]bool{
					staking.Address{}: true,
				},
			},
			staking.Address{},
			true,
		},
	} {
		require.Equal(t, tt.permitted, isTransferPermitted(tt.params, tt.fromAddr), tt.msg)
	}
}
