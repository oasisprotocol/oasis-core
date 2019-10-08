package staking

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/keyformat"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	// accountKeyFmt is the key format used for accounts.
	//
	// Value is a CBOR-serialized account.
	accountKeyFmt = keyformat.New(0x50, &signature.MapKey{})
	// thresholdKeyFmt is the key format used for thresholds.
	//
	// Value is a CBOR-serialized threshold.
	thresholdKeyFmt = keyformat.New(0x51, uint64(0))
	// totalSupplyKeyFmt is the key format used for the total supply.
	//
	// Value is a CBOR-serialized quantity.
	totalSupplyKeyFmt = keyformat.New(0x52)
	// commonPoolKeyFmt is the key format used for the common pool balance.
	//
	// Value is a CBOR-serialized quantity.
	commonPoolKeyFmt = keyformat.New(0x53)
	// debondingIntervalKeyFmt is the key format used for the debonding interval parameter.
	//
	// Value is a little endian encoding of an uint64.
	debondingIntervalKeyFmt = keyformat.New(0x54)
	// acceptableTransferPeersKeyFmt is the key format used for the acceptable transfer peers set.
	//
	// Value is a CBOR-serialized map from acceptable runtime IDs the boolean true.
	acceptableTransferPeersKeyFmt = keyformat.New(0x55)
)

type ledgerEntry struct {
	GeneralBalance  staking.Quantity `json:"general_balance"`
	EscrowBalance   staking.Quantity `json:"escrow_balance"`
	DebondStartTime uint64           `json:"debond_start_time"`
	Nonce           uint64           `json:"nonce"`
}

type immutableState struct {
	*abci.ImmutableState
}

func (s *immutableState) totalSupply() (*staking.Quantity, error) {
	_, value := s.Snapshot.Get(totalSupplyKeyFmt.Encode())
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
	_, value := s.Snapshot.Get(commonPoolKeyFmt.Encode())
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
	_, value := s.Snapshot.Get(debondingIntervalKeyFmt.Encode())
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
	s.Snapshot.IterateRange(
		thresholdKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var k uint64
			if !thresholdKeyFmt.Decode(key, &k) {
				return true
			}

			var q staking.Quantity
			if err := cbor.Unmarshal(value, &q); err != nil {
				panic("staking: corrput state: " + err.Error())
			}

			m[staking.ThresholdKind(k)] = q

			return false
		},
	)

	return m, nil
}

func (s *immutableState) accounts() ([]signature.PublicKey, error) {
	var accounts []signature.PublicKey
	s.Snapshot.IterateRange(
		accountKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var id signature.PublicKey
			if !accountKeyFmt.Decode(key, &id) {
				return true
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
	_, value := s.Snapshot.Get(accountKeyFmt.Encode(&id))
	if value == nil {
		return &ledgerEntry{}
	}

	var ent ledgerEntry
	if err := cbor.Unmarshal(value, &ent); err != nil {
		panic("staking: corrupt account state: " + err.Error())
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
	s.tree.Set(accountKeyFmt.Encode(&id), cbor.Marshal(account))
}

// SetDebondStartTime sets the debonding start time of an account to ts.
func (s *MutableState) SetDebondStartTime(id signature.PublicKey, ts uint64) {
	account := s.account(id)
	account.DebondStartTime = ts
	s.setAccount(id, account)
}

func (s *MutableState) setTotalSupply(q *staking.Quantity) {
	s.tree.Set(totalSupplyKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) setCommonPool(q *staking.Quantity) {
	s.tree.Set(commonPoolKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) setDebondingInterval(interval uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], interval)
	s.tree.Set(debondingIntervalKeyFmt.Encode(), tmp[:])
}

func (s *MutableState) setAcceptableTransferPeers(peers map[signature.MapKey]bool) {
	s.tree.Set(acceptableTransferPeersKeyFmt.Encode(), cbor.Marshal(peers))
}

func (s *MutableState) setThreshold(kind staking.ThresholdKind, q *staking.Quantity) {
	s.tree.Set(thresholdKeyFmt.Encode(uint64(kind)), cbor.Marshal(q))
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

func (s *MutableState) isAcceptableTransferPeer(runtimeID signature.PublicKey) (bool, error) {
	_, value := s.Snapshot.Get(acceptableTransferPeersKeyFmt.Encode())
	if value == nil {
		return false, nil
	}

	var peers map[signature.MapKey]bool
	if err := cbor.Unmarshal(value, &peers); err != nil {
		return false, err
	}
	return peers[runtimeID.ToMapKey()], nil
}

func (s *MutableState) HandleRoothashMessage(runtimeID signature.PublicKey, message *block.RoothashMessage) (error, error) {
	if message.StakingGeneralAdjustmentRoothashMessage != nil {
		acceptable, err := s.isAcceptableTransferPeer(runtimeID)
		if err != nil {
			return nil, errors.Wrap(err, "state corrupted")
		}
		if !acceptable {
			return errors.Errorf("staking general adjustment message received from unacceptable runtime %s", runtimeID), nil
		}

		account := s.account(message.StakingGeneralAdjustmentRoothashMessage.Account)

		switch message.StakingGeneralAdjustmentRoothashMessage.Op {
		case block.Increase:
			err = account.GeneralBalance.Add(message.StakingGeneralAdjustmentRoothashMessage.Amount)
		case block.Decrease:
			err = account.GeneralBalance.Sub(message.StakingGeneralAdjustmentRoothashMessage.Amount)
		default:
			return errors.Errorf("staking general adjustment message has invalid op"), nil
		}
		if err != nil {
			return errors.Wrapf(err, "couldn't apply adjustment in staking general adjustment message"), nil
		}

		s.setAccount(message.StakingGeneralAdjustmentRoothashMessage.Account, account)
	}

	return nil, nil
}

// NewMutableState creates a new mutable staking state wrapper.
func NewMutableState(tree *iavl.MutableTree) *MutableState {
	inner := &abci.ImmutableState{Snapshot: tree.ImmutableTree}

	return &MutableState{
		immutableState: &immutableState{inner},
		tree:           tree,
	}
}
