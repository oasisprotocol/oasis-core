package followtool

import (
	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	stakingstate "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
)

func checkNonzeroSupply(state *iavl.MutableTree) error {
	// The total supply should never fall to zero.

	st := stakingstate.NewMutableState(state)

	totalSupply, err := st.TotalSupply()
	if err != nil {
		return errors.Wrap(err, "TotalSupply")
	}

	if totalSupply.IsZero() {
		return errors.New("total supply is zero")
	}
	logger.Debug("total supply okay")

	return nil
}
