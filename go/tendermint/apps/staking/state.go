package staking

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

const (
	stateAccountsMap   = "staking/accounts/%s"
	stateThresholdsMap = "staking/thresholds/%d"
)

var (
	stateTotalSupply       = []byte("staking/total_supply")
	stateCommonPool        = []byte("staking/common_pool")
	stateDebondingInterval = []byte("staking/debonding_interval")
)

type ledgerEntry struct {
	GeneralBalance  staking.Quantity `codec:"general_balance"`
	EscrowBalance   staking.Quantity `codec:"escrow_balance"`
	DebondStartTime uint64           `codec:"debond_start_time"`
	Nonce           uint64           `codec:"nonce"`

	Approvals map[signature.MapKey]*staking.Quantity `codec:"approvals"`
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

// CommonPool returns the balance of the global common pool.
func (s *immutableState) CommonPool() (*staking.Quantity, error) {
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
	q, err := s.CommonPool()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(q), nil
}

func (s *immutableState) debondingInterval() (uint64, error) {
	_, value := s.Snapshot.Get(stateDebondingInterval)
	if len(value) != 8 {
		return 0, fmt.Errorf("staking: corrupt debonding interval")
	}

	return binary.LittleEndian.Uint64(value), nil
}

func (s *immutableState) rawDebondingInterval() ([]byte, error) {
	q, err := s.debondingInterval()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(q), nil
}

// Thresholds returns the currently configured thresholds if any.
func (s *immutableState) Thresholds() (map[staking.ThresholdKind]staking.Quantity, error) {
	m := make(map[staking.ThresholdKind]staking.Quantity)
	s.Snapshot.IterateRangeInclusive(
		[]byte(fmt.Sprintf(stateThresholdsMap, staking.KindValidator)),
		[]byte(fmt.Sprintf(stateThresholdsMap, staking.KindMax)),
		true,
		func(key, value []byte, version int64) bool {
			var k staking.ThresholdKind
			if _, err := fmt.Sscanf(string(key), stateThresholdsMap, &k); err != nil {
				panic("staking: corrupt key: " + err.Error())
			}

			var q staking.Quantity
			if err := cbor.Unmarshal(value, &q); err != nil {
				panic("staking: corrput state: " + err.Error())
			}

			m[k] = q

			return false
		},
	)

	return m, nil
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

// EscrowBalance returns the escrow balance for the ID.
func (s *immutableState) EscrowBalance(id signature.PublicKey) *staking.Quantity {
	account := s.account(id)
	return account.EscrowBalance.Clone()
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

// SetDebondStartTime sets the debonding start time of an account to ts.
func (s *MutableState) SetDebondStartTime(id signature.PublicKey, ts uint64) {
	account := s.account(id)
	account.DebondStartTime = ts
	s.setAccount(id, account)
}

func (s *MutableState) setTotalSupply(q *staking.Quantity) {
	s.tree.Set(stateTotalSupply, cbor.Marshal(q))
}

func (s *MutableState) setCommonPool(q *staking.Quantity) {
	s.tree.Set(stateCommonPool, cbor.Marshal(q))
}

func (s *MutableState) setDebondingInterval(interval uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], interval)
	s.tree.Set(stateDebondingInterval, tmp[:])
}

func (s *MutableState) setThreshold(kind staking.ThresholdKind, q *staking.Quantity) {
	s.tree.Set([]byte(fmt.Sprintf(stateThresholdsMap, kind)), cbor.Marshal(q))
}

// SlashEscrow slashes up to the amount from the escrow balance of the account,
// transfering it to the global common pool, returning true iff the amount
// actually slashed is > 0.
//
// WARNING: This is an internal routine to be used to implement staking policy,
// and MUST NOT be exposed outside of backend implementations.
func (s *MutableState) SlashEscrow(ctx *abci.Context, fromID signature.PublicKey, amount *staking.Quantity) (bool, error) {
	commonPool, err := s.CommonPool()
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to query common pool for slash ")
	}

	from := s.account(fromID)
	slashed, err := staking.MoveUpTo(commonPool, &from.EscrowBalance, amount)
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to slash")
	}

	ret := !slashed.IsZero()
	if ret {
		s.setCommonPool(commonPool)
		s.setAccount(fromID, from)

		if !ctx.IsCheckOnly() {
			ev := cbor.Marshal(&staking.TakeEscrowEvent{
				Owner:  fromID,
				Tokens: *slashed,
			})
			ctx.EmitTag(TagTakeEscrow, ev)
		}
	}

	return ret, nil
}

// TransferFromCommon transfers up to the amount from the global common pool
// to the general balance of the account, returning true iff the
// amount transfered is > 0.
//
// WARNING: This is an internal routine to be used to implement incentivization
// policy, and MUST NOT be exposed outside of backend implementations.
func (s *MutableState) TransferFromCommon(ctx *abci.Context, toID signature.PublicKey, amount *staking.Quantity) (bool, error) {
	commonPool, err := s.CommonPool()
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to query common pool for transfer")
	}

	to := s.account(toID)
	transfered, err := staking.MoveUpTo(&to.GeneralBalance, commonPool, amount)
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to transfer from common pool")
	}

	ret := !transfered.IsZero()
	if ret {
		s.setCommonPool(commonPool)
		s.setAccount(toID, to)

		if !ctx.IsCheckOnly() {
			ev := cbor.Marshal(&staking.TransferEvent{
				// XXX: Reserve an id for the common pool?
				To:     toID,
				Tokens: *transfered,
			})
			ctx.EmitTag(TagTransfer, ev)
		}
	}

	return ret, nil
}

// NewMutableState creates a new mutable staking state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
