package staking

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

var (
	// accountKeyFmt is the key format used for accounts (account id).
	//
	// Value is a CBOR-serialized account.
	accountKeyFmt = keyformat.New(0x50, &signature.MapKey{})
	// thresholdKeyFmt is the key format used for thresholds (kind).
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
	// delegationKeyFmt is the key format used for delegations (escrow id, delegator id).
	//
	// Value is CBOR-serialized delegation.
	delegationKeyFmt = keyformat.New(0x55, &signature.MapKey{}, &signature.MapKey{})
	// debondingDelegationKeyFmt is the key format used for debonding delegations
	// (delegator id, escrow id, seq no).
	//
	// Value is CBOR-serialized debonding delegation.
	debondingDelegationKeyFmt = keyformat.New(0x56, &signature.MapKey{}, &signature.MapKey{}, uint64(0))
	// debondingQueueKeyFmt is the debonding queue key format (epoch, delegator id,
	// escrow id, seq no).
	//
	// Value is empty.
	debondingQueueKeyFmt = keyformat.New(0x57, uint64(0), &signature.MapKey{}, &signature.MapKey{}, uint64(0))
	// acceptableTransferPeersKeyFmt is the key format used for the acceptable transfer peers set.
	//
	// Value is a CBOR-serialized map from acceptable runtime IDs to the boolean true.
	acceptableTransferPeersKeyFmt = keyformat.New(0x58)

	logger = logging.GetLogger("tendermint/staking")
)

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

func (s *immutableState) accountRaw(id signature.PublicKey) []byte {
	_, value := s.Snapshot.Get(accountKeyFmt.Encode(&id))
	return value
}

func (s *immutableState) account(id signature.PublicKey) *staking.Account {
	value := s.accountRaw(id)
	if value == nil {
		return &staking.Account{}
	}

	var ent staking.Account
	if err := cbor.Unmarshal(value, &ent); err != nil {
		panic("staking: corrupt account state: " + err.Error())
	}
	return &ent
}

// EscrowBalance returns the escrow balance for the ID.
func (s *immutableState) EscrowBalance(id signature.PublicKey) *staking.Quantity {
	account := s.account(id)

	balance := account.Escrow.Balance.Clone()
	// Subtract the amount currently undergoing debonding.
	debonding, err := staking.TokensForShares(&account.Escrow, &account.Escrow.DebondingShares)
	if err != nil {
		panic("staking: failed to compute escrow balance: " + err.Error())
	}
	if err = balance.Sub(debonding); err != nil {
		panic("staking: failed to compute escrow balance: " + err.Error())
	}

	return balance
}

func (s *immutableState) delegations() (map[signature.MapKey]map[signature.MapKey]*staking.Delegation, error) {
	delegations := make(map[signature.MapKey]map[signature.MapKey]*staking.Delegation)
	s.Snapshot.IterateRange(
		delegationKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var escrowID signature.MapKey
			var delegatorID signature.MapKey
			if !delegationKeyFmt.Decode(key, &escrowID, &delegatorID) {
				return true
			}

			var del staking.Delegation
			if err := cbor.Unmarshal(value, &del); err != nil {
				panic("staking: corrupt delegation state: " + err.Error())
			}

			if delegations[escrowID] == nil {
				delegations[escrowID] = make(map[signature.MapKey]*staking.Delegation)
			}
			delegations[escrowID][delegatorID] = &del

			return false
		},
	)

	return delegations, nil
}

func (s *immutableState) delegationRaw(delegatorID, escrowID signature.PublicKey) []byte {
	_, value := s.Snapshot.Get(delegationKeyFmt.Encode(&escrowID, &delegatorID))
	return value
}

func (s *immutableState) delegation(delegatorID, escrowID signature.PublicKey) *staking.Delegation {
	value := s.delegationRaw(delegatorID, escrowID)
	if value == nil {
		return &staking.Delegation{}
	}

	var del staking.Delegation
	if err := cbor.Unmarshal(value, &del); err != nil {
		panic("staking: corrupt delegation state: " + err.Error())
	}
	return &del
}

func (s *immutableState) debondingDelegations() (map[signature.MapKey]map[signature.MapKey][]*staking.DebondingDelegation, error) {
	delegations := make(map[signature.MapKey]map[signature.MapKey][]*staking.DebondingDelegation)
	s.Snapshot.IterateRange(
		debondingDelegationKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var escrowID signature.MapKey
			var delegatorID signature.MapKey
			if !debondingDelegationKeyFmt.Decode(key, &delegatorID, &escrowID) {
				return true
			}

			var deb staking.DebondingDelegation
			if err := cbor.Unmarshal(value, &deb); err != nil {
				panic("staking: corrupt debonding delegation state: " + err.Error())
			}

			if delegations[escrowID] == nil {
				delegations[escrowID] = make(map[signature.MapKey][]*staking.DebondingDelegation)
			}
			delegations[escrowID][delegatorID] = append(delegations[escrowID][delegatorID], &deb)

			return false
		},
	)

	return delegations, nil
}

func (s *immutableState) debondingDelegationsFor(delegatorID signature.PublicKey) (map[signature.MapKey][]*staking.DebondingDelegation, error) {
	delegations := make(map[signature.MapKey][]*staking.DebondingDelegation)
	s.Snapshot.IterateRange(
		debondingDelegationKeyFmt.Encode(&delegatorID),
		nil,
		true,
		func(key, value []byte) bool {
			var escrowID signature.MapKey
			var decDelegatorID signature.PublicKey
			if !debondingDelegationKeyFmt.Decode(key, &decDelegatorID, &escrowID) || !decDelegatorID.Equal(delegatorID) {
				return true
			}

			var deb staking.DebondingDelegation
			if err := cbor.Unmarshal(value, &deb); err != nil {
				panic("staking: corrupt debonding delegation state: " + err.Error())
			}

			delegations[escrowID] = append(delegations[escrowID], &deb)

			return false
		},
	)

	return delegations, nil
}

func (s *immutableState) debondingDelegation(delegatorID, escrowID signature.PublicKey, seq uint64) *staking.DebondingDelegation {
	_, value := s.Snapshot.Get(debondingDelegationKeyFmt.Encode(&delegatorID, &escrowID, seq))
	if value == nil {
		return &staking.DebondingDelegation{}
	}

	var deb staking.DebondingDelegation
	if err := cbor.Unmarshal(value, &deb); err != nil {
		panic("staking: corrupt debonding delegation state: " + err.Error())
	}
	return &deb
}

type debondingQueueEntry struct {
	epoch       epochtime.EpochTime
	delegatorID signature.PublicKey
	escrowID    signature.PublicKey
	seq         uint64
	delegation  *staking.DebondingDelegation
}

func (s *immutableState) expiredDebondingQueue(epoch epochtime.EpochTime) []*debondingQueueEntry {
	var entries []*debondingQueueEntry
	s.Snapshot.IterateRange(
		debondingQueueKeyFmt.Encode(),
		debondingQueueKeyFmt.Encode(uint64(epoch)+1),
		true,
		func(key, value []byte) bool {
			var decEpoch, seq uint64
			var escrowID signature.PublicKey
			var delegatorID signature.PublicKey
			if !debondingQueueKeyFmt.Decode(key, &decEpoch, &delegatorID, &escrowID, &seq) {
				return true
			}

			deb := s.debondingDelegation(delegatorID, escrowID, seq)
			entries = append(entries, &debondingQueueEntry{
				epoch:       epochtime.EpochTime(decEpoch),
				delegatorID: delegatorID,
				escrowID:    escrowID,
				seq:         seq,
				delegation:  deb,
			})

			return false
		},
	)
	return entries
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

func (s *MutableState) setAccount(id signature.PublicKey, account *staking.Account) {
	s.tree.Set(accountKeyFmt.Encode(&id), cbor.Marshal(account))
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

func (s *MutableState) setDelegation(delegatorID, escrowID signature.PublicKey, d *staking.Delegation) {
	// Remove delegation if there are no more shares in it.
	if d.Shares.IsZero() {
		s.tree.Remove(delegationKeyFmt.Encode(&escrowID, &delegatorID))
		return
	}

	s.tree.Set(delegationKeyFmt.Encode(&escrowID, &delegatorID), cbor.Marshal(d))
}

func (s *MutableState) setDebondingDelegation(delegatorID, escrowID signature.PublicKey, seq uint64, d *staking.DebondingDelegation) {
	key := debondingDelegationKeyFmt.Encode(&delegatorID, &escrowID, seq)

	if d == nil {
		// Remove descriptor.
		s.tree.Remove(key)
		return
	}

	// Add to debonding queue.
	s.tree.Set(debondingQueueKeyFmt.Encode(uint64(d.DebondEndTime), &delegatorID, &escrowID, seq), []byte{})
	// Add descriptor.
	s.tree.Set(key, cbor.Marshal(d))
}

func (s *MutableState) removeFromDebondingQueue(epoch epochtime.EpochTime, delegatorID, escrowID signature.PublicKey, seq uint64) {
	s.tree.Remove(debondingQueueKeyFmt.Encode(uint64(epoch), &delegatorID, &escrowID, seq))
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
	slashed, err := staking.MoveUpTo(commonPool, &from.Escrow.Balance, amount)
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
	transfered, err := staking.MoveUpTo(&to.General.Balance, commonPool, amount)
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
			err = account.General.Balance.Add(message.StakingGeneralAdjustmentRoothashMessage.Amount)
		case block.Decrease:
			err = account.General.Balance.Sub(message.StakingGeneralAdjustmentRoothashMessage.Amount)
		default:
			return errors.Errorf("staking general adjustment message has invalid op"), nil
		}
		if err != nil {
			return errors.Wrapf(err, "couldn't apply adjustment in staking general adjustment message"), nil
		}

		s.setAccount(message.StakingGeneralAdjustmentRoothashMessage.Account, account)
		logger.Debug("handled StakingGeneralAdjustmentRoothashMessage",
			logging.LogEvent, staking.LogEventGeneralAdjustment,
			"account", message.StakingGeneralAdjustmentRoothashMessage.Account,
			"general_balance_after", account.General.Balance,
		)
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
