package staking

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func TestIsTransferPermitted(t *testing.T) {
	for _, tt := range []struct {
		msg       string
		params    *staking.ConsensusParameters
		fromID    signature.PublicKey
		permitted bool
	}{
		{
			"no disablement",
			&staking.ConsensusParameters{},
			signature.PublicKey{},
			true,
		},
		{
			"all disabled",
			&staking.ConsensusParameters{
				DisableTransfers: true,
			},
			signature.PublicKey{},
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
			true,
		},
	} {
		require.Equal(t, tt.permitted, isTransferPermitted(tt.params, tt.fromID), tt.msg)
	}
}
