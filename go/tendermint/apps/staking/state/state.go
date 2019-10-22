package state

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
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

var (
	// AppName is the ABCI application name.
	AppName = "100_staking"
	// KeyTakeEscrow is an ABCI event attribute key for TakeEscrow calls
	// (value is an app.TakeEscrowEvent).
	KeyTakeEscrow = []byte("take_escrow")
	// KeyTransfer is an ABCI event attribute key for Transfers (value is
	// an app.TransferEvent).
	KeyTransfer = []byte("transfer")

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
	// slashingKeyFmt is the key format used for the slashing table.
	//
	// Value is CBOR-serialized map from slash reason to slash descriptor.
	slashingKeyFmt = keyformat.New(0x59)

	logger = logging.GetLogger("tendermint/staking")
)

type ImmutableState struct {
	*abci.ImmutableState
}

func (s *ImmutableState) TotalSupply() (*staking.Quantity, error) {
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

// CommonPool returns the balance of the global common pool.
func (s *ImmutableState) CommonPool() (*staking.Quantity, error) {
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

func (s *ImmutableState) DebondingInterval() (uint64, error) {
	_, value := s.Snapshot.Get(debondingIntervalKeyFmt.Encode())
	if len(value) != 8 {
		return 0, fmt.Errorf("staking: corrupt debonding interval")
	}

	return binary.LittleEndian.Uint64(value), nil
}

func (s *ImmutableState) AcceptableTransferPeers() (map[signature.MapKey]bool, error) {
	_, value := s.Snapshot.Get(acceptableTransferPeersKeyFmt.Encode())
	if value == nil {
		return make(map[signature.MapKey]bool), nil
	}

	var peers map[signature.MapKey]bool
	if err := cbor.Unmarshal(value, &peers); err != nil {
		return nil, err
	}

	return peers, nil
}

func (s *ImmutableState) isAcceptableTransferPeer(runtimeID signature.PublicKey) (bool, error) {
	peers, err := s.AcceptableTransferPeers()
	if err != nil {
		return false, err
	}
	return peers[runtimeID.ToMapKey()], nil
}

// Thresholds returns the currently configured thresholds if any.
func (s *ImmutableState) Thresholds() (map[staking.ThresholdKind]staking.Quantity, error) {
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

func (s *ImmutableState) Accounts() ([]signature.PublicKey, error) {
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

func (s *ImmutableState) Account(id signature.PublicKey) *staking.Account {
	_, value := s.Snapshot.Get(accountKeyFmt.Encode(&id))
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
func (s *ImmutableState) EscrowBalance(id signature.PublicKey) *staking.Quantity {
	account := s.Account(id)

	return account.Escrow.Active.Balance.Clone()
}

func (s *ImmutableState) Delegations() (map[signature.MapKey]map[signature.MapKey]*staking.Delegation, error) {
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

func (s *ImmutableState) Delegation(delegatorID, escrowID signature.PublicKey) *staking.Delegation {
	_, value := s.Snapshot.Get(delegationKeyFmt.Encode(&escrowID, &delegatorID))
	if value == nil {
		return &staking.Delegation{}
	}

	var del staking.Delegation
	if err := cbor.Unmarshal(value, &del); err != nil {
		panic("staking: corrupt delegation state: " + err.Error())
	}
	return &del
}

func (s *ImmutableState) DebondingDelegations() (map[signature.MapKey]map[signature.MapKey][]*staking.DebondingDelegation, error) {
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

func (s *ImmutableState) DebondingDelegationsFor(delegatorID signature.PublicKey) (map[signature.MapKey][]*staking.DebondingDelegation, error) {
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

func (s *ImmutableState) DebondingDelegation(delegatorID, escrowID signature.PublicKey, seq uint64) *staking.DebondingDelegation {
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

type DebondingQueueEntry struct {
	Epoch       epochtime.EpochTime
	DelegatorID signature.PublicKey
	EscrowID    signature.PublicKey
	Seq         uint64
	Delegation  *staking.DebondingDelegation
}

func (s *ImmutableState) ExpiredDebondingQueue(epoch epochtime.EpochTime) []*DebondingQueueEntry {
	var entries []*DebondingQueueEntry
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

			deb := s.DebondingDelegation(delegatorID, escrowID, seq)
			entries = append(entries, &DebondingQueueEntry{
				Epoch:       epochtime.EpochTime(decEpoch),
				DelegatorID: delegatorID,
				EscrowID:    escrowID,
				Seq:         seq,
				Delegation:  deb,
			})

			return false
		},
	)
	return entries
}

func (s *ImmutableState) Slashing() (map[staking.SlashReason]staking.Slash, error) {
	_, value := s.Snapshot.Get(slashingKeyFmt.Encode())
	if value == nil {
		return make(map[staking.SlashReason]staking.Slash), nil
	}

	var st map[staking.SlashReason]staking.Slash
	if err := cbor.Unmarshal(value, &st); err != nil {
		return nil, err
	}
	return st, nil
}

func NewImmutableState(state *abci.ApplicationState, version int64) (*ImmutableState, error) {
	inner, err := abci.NewImmutableState(state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{inner}, nil
}

// MutableState is a mutable staking state wrapper.
type MutableState struct {
	*ImmutableState

	tree *iavl.MutableTree
}

func (s *MutableState) SetAccount(id signature.PublicKey, account *staking.Account) {
	s.tree.Set(accountKeyFmt.Encode(&id), cbor.Marshal(account))
}

func (s *MutableState) SetTotalSupply(q *staking.Quantity) {
	s.tree.Set(totalSupplyKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) SetCommonPool(q *staking.Quantity) {
	s.tree.Set(commonPoolKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) SetDebondingInterval(interval uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], interval)
	s.tree.Set(debondingIntervalKeyFmt.Encode(), tmp[:])
}

func (s *MutableState) SetAcceptableTransferPeers(peers map[signature.MapKey]bool) {
	s.tree.Set(acceptableTransferPeersKeyFmt.Encode(), cbor.Marshal(peers))
}

func (s *MutableState) SetThreshold(kind staking.ThresholdKind, q *staking.Quantity) {
	s.tree.Set(thresholdKeyFmt.Encode(uint64(kind)), cbor.Marshal(q))
}

func (s *MutableState) SetDelegation(delegatorID, escrowID signature.PublicKey, d *staking.Delegation) {
	// Remove delegation if there are no more shares in it.
	if d.Shares.IsZero() {
		s.tree.Remove(delegationKeyFmt.Encode(&escrowID, &delegatorID))
		return
	}

	s.tree.Set(delegationKeyFmt.Encode(&escrowID, &delegatorID), cbor.Marshal(d))
}

func (s *MutableState) SetDebondingDelegation(delegatorID, escrowID signature.PublicKey, seq uint64, d *staking.DebondingDelegation) {
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

func (s *MutableState) RemoveFromDebondingQueue(epoch epochtime.EpochTime, delegatorID, escrowID signature.PublicKey, seq uint64) {
	s.tree.Remove(debondingQueueKeyFmt.Encode(uint64(epoch), &delegatorID, &escrowID, seq))
}

func (s *MutableState) SetSlashing(value map[staking.SlashReason]staking.Slash) {
	s.tree.Set(slashingKeyFmt.Encode(), cbor.Marshal(value))
}

func slashPool(dst *staking.Quantity, p *staking.SharePool, share *staking.Quantity) error {
	slashAmount := p.Balance.Clone()
	if err := slashAmount.Mul(share); err != nil {
		return errors.Wrap(err, "slashAmount.Mul")
	}
	if err := slashAmount.Quo(staking.SlashAmountDenominator); err != nil {
		return errors.Wrap(err, "slashAmount.Quo")
	}

	if err := staking.Move(dst, &p.Balance, slashAmount); err != nil {
		return errors.Wrap(err, "moving tokens")
	}

	return nil
}

// SlashEscrow slashes the escrow balance and the escrow-but-undergoing-debonding
// balance of the account, transferring it to the global common pool, returning
// true iff the amount actually slashed is > 0.
//
// WARNING: This is an internal routine to be used to implement staking policy,
// and MUST NOT be exposed outside of backend implementations.
func (s *MutableState) SlashEscrow(ctx *abci.Context, fromID signature.PublicKey, share *staking.Quantity) (bool, error) {
	commonPool, err := s.CommonPool()
	if err != nil {
		return false, fmt.Errorf("staking: failed to query common pool for slash: %w", err)
	}

	// Compute actual token amount based on passed percentage.
	from := s.Account(fromID)

	var slashed staking.Quantity
	if err = slashPool(&slashed, &from.Escrow.Active, share); err != nil {
		return false, errors.Wrap(err, "slashing active escrow")
	}
	if err = slashPool(&slashed, &from.Escrow.Debonding, share); err != nil {
		return false, errors.Wrap(err, "slashing debonding escrow")
	}

	if slashed.IsZero() {
		return false, nil
	}

	totalSlashed := slashed.Clone()

	if err = staking.Move(commonPool, &slashed, totalSlashed); err != nil {
		return false, errors.Wrap(err, "moving tokens to common pool")
	}

	s.SetCommonPool(commonPool)
	s.SetAccount(fromID, from)

	if !ctx.IsCheckOnly() {
		ev := cbor.Marshal(&staking.TakeEscrowEvent{
			Owner:  fromID,
			Tokens: *totalSlashed,
		})
		ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyTakeEscrow, ev))
	}

	return true, nil
}

// TransferFromCommon transfers up to the amount from the global common pool
// to the general balance of the account, returning true iff the
// amount transferred is > 0.
//
// WARNING: This is an internal routine to be used to implement incentivization
// policy, and MUST NOT be exposed outside of backend implementations.
func (s *MutableState) TransferFromCommon(ctx *abci.Context, toID signature.PublicKey, amount *staking.Quantity) (bool, error) {
	commonPool, err := s.CommonPool()
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to query common pool for transfer")
	}

	to := s.Account(toID)
	transfered, err := staking.MoveUpTo(&to.General.Balance, commonPool, amount)
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to transfer from common pool")
	}

	ret := !transfered.IsZero()
	if ret {
		s.SetCommonPool(commonPool)
		s.SetAccount(toID, to)

		if !ctx.IsCheckOnly() {
			ev := cbor.Marshal(&staking.TransferEvent{
				// XXX: Reserve an id for the common pool?
				To:     toID,
				Tokens: *transfered,
			})
			ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyTransfer, ev))
		}
	}

	return ret, nil
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

		account := s.Account(message.StakingGeneralAdjustmentRoothashMessage.Account)

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

		s.SetAccount(message.StakingGeneralAdjustmentRoothashMessage.Account, account)
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
		ImmutableState: &ImmutableState{inner},
		tree:           tree,
	}
}
