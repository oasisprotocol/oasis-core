package staking

import (
	"fmt"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const stateAccountsMap = "staking/accounts/%s"

var (
	stateTotalSupply = []byte("staking/total_supply")
	stateCommonPool  = []byte("staking/common_pool")
)

type ledgerEntry struct {
	GeneralBalance staking.Quantity `codec:"general_balance"`
	EscrowBalance  staking.Quantity `codec:"escrow_balance"`
	Nonce          uint64           `codec:"nonce"`

	Approvals map[signature.MapKey]*staking.Quantity `codec:"approvals"` // XXX; Separate?
}

func (ent *ledgerEntry) getAllowance(id signature.PublicKey) *staking.Quantity {
	if q := ent.Approvals[id.ToMapKey()]; q != nil {
		return q.Clone()
	}
	return &staking.Quantity{}
}

func (ent *ledgerEntry) setAllowance(id signature.PublicKey, n *staking.Quantity) {
	if n.IsZero() {
		delete(ent.Approvals, id.ToMapKey())
	} else {
		ent.Approvals[id.ToMapKey()] = n.Clone()
	}
}

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) totalSupply() (*staking.Quantity, error) {
	_, value := s.Snapshot.Get(stateTotalSupply)
	if value == nil {
		return &staking.Quantity{}, nil
	}

	var q staking.Quantity
	if err := cbor.Unmarshal(value, &q); err != nil {
		return nil, err
	}

	return &q, nil
}

func (s *immutableState) rawTotalSupply() ([]byte, error) {
	q, err := s.totalSupply()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(q), nil
}

func (s *immutableState) commonPool() (*staking.Quantity, error) {
	_, value := s.Snapshot.Get(stateCommonPool)
	if value == nil {
		return &staking.Quantity{}, nil
	}

	var q staking.Quantity
	if err := cbor.Unmarshal(value, &q); err != nil {
		return nil, err
	}

	return &q, nil
}

func (s *immutableState) rawCommonPool() ([]byte, error) {
	q, err := s.commonPool()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(q), nil
}

func (s *immutableState) accounts() ([]signature.PublicKey, error) {
	var accounts []signature.PublicKey
	s.Snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateAccountsMap, abci.FirstID)),
		[]byte(fmt.Sprintf(stateAccountsMap, abci.LastID)),
		true,
		func(key, value []byte, version int64) bool {
			var hexID string
			if _, err := fmt.Sscanf(string(key), stateAccountsMap, &hexID); err != nil {
				panic("staking: corrupt key" + err.Error())
			}

			var id signature.PublicKey
			if err := id.UnmarshalHex(hexID); err != nil {
				panic("staking: corrupt state: " + err.Error())
			}
			accounts = append(accounts, id)

			return false
		},
	)

	return accounts, nil
}

func (s *immutableState) rawAccounts() ([]byte, error) {
	accounts, err := s.accounts()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(accounts), nil
}

func (s *immutableState) account(id signature.PublicKey) *ledgerEntry {
	_, value := s.Snapshot.Get([]byte(fmt.Sprintf(stateAccountsMap, id)))
	if value == nil {
		return &ledgerEntry{
			Approvals: make(map[signature.MapKey]*staking.Quantity),
		}
	}

	var ent ledgerEntry
	if err := cbor.Unmarshal(value, &ent); err != nil {
		panic("staking: corrupt account state: " + err.Error())
	}
	if ent.Approvals == nil {
		ent.Approvals = make(map[signature.MapKey]*staking.Quantity)
	}
	return &ent
}

func newImmutableState(state *abci.ApplicationState, version int64) (*immutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &immutableState{inner}, nil
}

// MutableState is a mutable staking state wrapper.
type MutableState struct {
	*immutableState

	tree *iavl.MutableTree
}

func (s *MutableState) setAccount(id signature.PublicKey, account *ledgerEntry) {
	s.tree.Set([]byte(fmt.Sprintf(stateAccountsMap, id)), cbor.Marshal(account))
}

func (s *MutableState) setTotalSupply(q *staking.Quantity) {
	s.tree.Set(stateTotalSupply, cbor.Marshal(q))
}

func (s *MutableState) setCommonPool(q *staking.Quantity) {
	s.tree.Set(stateCommonPool, cbor.Marshal(q))
}

// NewMutableState creates a new mutable staking state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
