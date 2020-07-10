package scheduler

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

func TestDiffValidators(t *testing.T) {
	logger := logging.GetLogger("TestDiffValidators")
	powerOne := map[signature.PublicKey]int64{
		{}: 1,
	}
	powerTwo := map[signature.PublicKey]int64{
		{}: 2,
	}
	for _, tt := range []struct {
		msg     string
		current map[signature.PublicKey]int64
		pending map[signature.PublicKey]int64
		result  []types.ValidatorUpdate
	}{
		{
			msg:     "equal",
			current: powerOne,
			pending: powerOne,
			result:  nil,
		},
		{
			msg:     "add",
			current: nil,
			pending: powerOne,
			result: []types.ValidatorUpdate{
				api.PublicKeyToValidatorUpdate(signature.PublicKey{}, 1),
			},
		},
		{
			msg:     "change",
			current: powerOne,
			pending: powerTwo,
			result: []types.ValidatorUpdate{
				api.PublicKeyToValidatorUpdate(signature.PublicKey{}, 2),
			},
		},
		{
			msg:     "remove",
			current: powerOne,
			pending: nil,
			result: []types.ValidatorUpdate{
				api.PublicKeyToValidatorUpdate(signature.PublicKey{}, 0),
			},
		},
	} {
		require.Equal(t, tt.result, diffValidators(logger, tt.current, tt.pending), tt.msg)
	}
}
