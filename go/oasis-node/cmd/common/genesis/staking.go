// Package genesis implements common genesis document manipulation
// routines.
package genesis

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// AppendableStakingState is a staking genesis state that can be appended
// to an existing genesis document.
type AppendableStakingState struct {
	State           staking.Genesis
	DebugTestEntity bool
}

// AppendTo appends the staking genesis state to an existing genesis document.
// Any pre-existing state will be overwritten.
func (st *AppendableStakingState) AppendTo(doc *genesis.Document) error {
	if st.State.TokenSymbol == "" {
		return fmt.Errorf("genesis/staking: token symbol not set")
	}

	if st.DebugTestEntity {
		ent, _, err := entity.TestEntity()
		if err != nil {
			return fmt.Errorf("genesis/staking: failed to get test entity: %w", err)
		}
		entAddr := staking.NewAddress(ent.ID)

		// Ok then, we hold the world ransom for One Million Billion Yen.
		var q quantity.Quantity
		if err = q.FromBigInt(big.NewInt(1_000_000_000_000_000)); err != nil {
			return fmt.Errorf("genesis/staking: failed to allocate test entity stake: %w", err)
		}

		// Add the test entity's ledger entry.
		if st.State.Ledger[entAddr] != nil {
			return fmt.Errorf("genesis/staking: test entity already in ledger")
		}
		st.State.Ledger[entAddr] = &staking.Account{
			General: staking.GeneralAccount{
				Balance: q,
				Nonce:   0,
			},
			Escrow: staking.EscrowAccount{
				Active: staking.SharePool{
					Balance:     q,
					TotalShares: *quantity.NewFromUint64(1),
				},
			},
		}

		// Add a self-delegation for the test entity.
		if st.State.Delegations == nil {
			st.State.Delegations = make(map[staking.Address]map[staking.Address]*staking.Delegation)
		}
		if st.State.Delegations[entAddr] == nil {
			st.State.Delegations[entAddr] = make(map[staking.Address]*staking.Delegation)
		}
		if st.State.Delegations[entAddr][entAddr] != nil {
			return fmt.Errorf("gensis/staking: test entity already has a self-delegation")
		}
		st.State.Delegations[entAddr][entAddr] = &staking.Delegation{
			Shares: *quantity.NewFromUint64(1),
		}

		// Inflate the TotalSupply to account for the account's general and
		// escrow balances.
		_ = st.State.TotalSupply.Add(&q)
		_ = st.State.TotalSupply.Add(&q)
	}

	// Set zero thresholds for all staking kinds, if none set.
	if len(st.State.Parameters.Thresholds) == 0 {
		sq := *quantity.NewFromUint64(0)
		st.State.Parameters.Thresholds = map[staking.ThresholdKind]quantity.Quantity{
			staking.KindEntity:            sq,
			staking.KindNodeValidator:     sq,
			staking.KindNodeCompute:       sq,
			staking.KindNodeKeyManager:    sq,
			staking.KindRuntimeCompute:    sq,
			staking.KindRuntimeKeyManager: sq,
		}
	}

	doc.Staking = st.State

	return nil
}

func (st *AppendableStakingState) setDefaultFeeSplit() error {
	if st.State.Parameters.FeeSplitWeightVote.IsZero() {
		if err := st.State.Parameters.FeeSplitWeightVote.FromInt64(1); err != nil {
			return fmt.Errorf("genesis/staking: couldn't set default fee split: %w", err)
		}
	}
	return nil
}

// NewAppendableStakingState creates a new AppendableStakingState.
func NewAppendableStakingState() (*AppendableStakingState, error) {
	st := &AppendableStakingState{
		State: staking.Genesis{
			Ledger: make(map[staking.Address]*staking.Account),
			Parameters: staking.ConsensusParameters{
				DebondingInterval: 1, // Minimum valid debonding interval.
			},
		},
	}
	if err := st.setDefaultFeeSplit(); err != nil {
		return nil, err
	}

	return st, nil
}

// NewAppendableStakingStateFromFile creates a new AppendableStakingState
// from a JSON document.
func NewAppendableStakingStateFromFile(path string) (*AppendableStakingState, error) {
	st, err := NewAppendableStakingState()
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("genesis/staking: failed to load staking genesis state: %w", err)
	}
	if err = json.Unmarshal(b, &st.State); err != nil {
		return nil, fmt.Errorf("genesis/staking: failed to parse staking genesis state: %w", err)
	}
	if err := st.setDefaultFeeSplit(); err != nil {
		return nil, err
	}

	return st, nil
}
