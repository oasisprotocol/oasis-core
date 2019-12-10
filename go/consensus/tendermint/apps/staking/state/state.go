package state

import (
	"bytes"
	"fmt"
	"math"
	"sort"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
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
	accountKeyFmt = keyformat.New(0x50, &signature.PublicKey{})
	// totalSupplyKeyFmt is the key format used for the total supply.
	//
	// Value is a CBOR-serialized quantity.
	totalSupplyKeyFmt = keyformat.New(0x51)
	// commonPoolKeyFmt is the key format used for the common pool balance.
	//
	// Value is a CBOR-serialized quantity.
	commonPoolKeyFmt = keyformat.New(0x52)
	// delegationKeyFmt is the key format used for delegations (escrow id, delegator id).
	//
	// Value is CBOR-serialized delegation.
	delegationKeyFmt = keyformat.New(0x53, &signature.PublicKey{}, &signature.PublicKey{})
	// debondingDelegationKeyFmt is the key format used for debonding delegations
	// (delegator id, escrow id, seq no).
	//
	// Value is CBOR-serialized debonding delegation.
	debondingDelegationKeyFmt = keyformat.New(0x54, &signature.PublicKey{}, &signature.PublicKey{}, uint64(0))
	// debondingQueueKeyFmt is the debonding queue key format (epoch, delegator id,
	// escrow id, seq no).
	//
	// Value is empty.
	debondingQueueKeyFmt = keyformat.New(0x55, uint64(0), &signature.PublicKey{}, &signature.PublicKey{}, uint64(0))
	// parametersKeyFmt is the key format used for consensus parameters.
	//
	// Value is CBOR-serialized staking.ConsensusParameters.
	parametersKeyFmt = keyformat.New(0x56)
	// lastBlockFeesKeyFmt is the accumulated fee balance for the previous block.
	//
	// Value is CBOR-serialized quantity.
	lastBlockFeesKeyFmt = keyformat.New(0x57)
	// epochSigningKeyFmt is the key format for epoch signing information.
	//
	// Value is CBOR-serialized EpochSigning.
	epochSigningKeyFmt = keyformat.New(0x58)

	logger = logging.GetLogger("tendermint/staking")
)

type ImmutableState struct {
	*abci.ImmutableState
}

func (s *ImmutableState) TotalSupply() (*quantity.Quantity, error) {
	_, value := s.Snapshot.Get(totalSupplyKeyFmt.Encode())
	if value == nil {
		return &quantity.Quantity{}, nil
	}

	var q quantity.Quantity
	if err := cbor.Unmarshal(value, &q); err != nil {
		return nil, err
	}

	return &q, nil
}

// CommonPool returns the balance of the global common pool.
func (s *ImmutableState) CommonPool() (*quantity.Quantity, error) {
	_, value := s.Snapshot.Get(commonPoolKeyFmt.Encode())
	if value == nil {
		return &quantity.Quantity{}, nil
	}

	var q quantity.Quantity
	if err := cbor.Unmarshal(value, &q); err != nil {
		return nil, err
	}

	return &q, nil
}

func (s *ImmutableState) ConsensusParameters() (*staking.ConsensusParameters, error) {
	_, raw := s.Snapshot.Get(parametersKeyFmt.Encode())
	if raw == nil {
		return nil, errors.New("tendermint/staking: expected consensus parameters to be present in app state")
	}

	var params staking.ConsensusParameters
	err := cbor.Unmarshal(raw, &params)
	return &params, err
}

func (s *ImmutableState) DebondingInterval() (epochtime.EpochTime, error) {
	params, err := s.ConsensusParameters()
	if err != nil {
		return epochtime.EpochInvalid, err
	}

	return params.DebondingInterval, nil
}

func (s *ImmutableState) RewardSchedule() ([]staking.RewardStep, error) {
	params, err := s.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	return params.RewardSchedule, nil
}

func (s *ImmutableState) CommissionScheduleRules() (*staking.CommissionScheduleRules, error) {
	params, err := s.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	return &params.CommissionScheduleRules, nil
}

func (s *ImmutableState) AcceptableTransferPeers() (map[signature.PublicKey]bool, error) {
	params, err := s.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	return params.AcceptableTransferPeers, nil
}

func (s *ImmutableState) isAcceptableTransferPeer(runtimeID signature.PublicKey) (bool, error) {
	peers, err := s.AcceptableTransferPeers()
	if err != nil {
		return false, err
	}
	return peers[runtimeID], nil
}

// Thresholds returns the currently configured thresholds if any.
func (s *ImmutableState) Thresholds() (map[staking.ThresholdKind]quantity.Quantity, error) {
	params, err := s.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	return params.Thresholds, nil
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
func (s *ImmutableState) EscrowBalance(id signature.PublicKey) *quantity.Quantity {
	account := s.Account(id)

	return account.Escrow.Active.Balance.Clone()
}

func (s *ImmutableState) Delegations() (map[signature.PublicKey]map[signature.PublicKey]*staking.Delegation, error) {
	delegations := make(map[signature.PublicKey]map[signature.PublicKey]*staking.Delegation)
	s.Snapshot.IterateRange(
		delegationKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var escrowID signature.PublicKey
			var delegatorID signature.PublicKey
			if !delegationKeyFmt.Decode(key, &escrowID, &delegatorID) {
				return true
			}

			var del staking.Delegation
			if err := cbor.Unmarshal(value, &del); err != nil {
				panic("staking: corrupt delegation state: " + err.Error())
			}

			if delegations[escrowID] == nil {
				delegations[escrowID] = make(map[signature.PublicKey]*staking.Delegation)
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

func (s *ImmutableState) DebondingDelegations() (map[signature.PublicKey]map[signature.PublicKey][]*staking.DebondingDelegation, error) {
	delegations := make(map[signature.PublicKey]map[signature.PublicKey][]*staking.DebondingDelegation)
	s.Snapshot.IterateRange(
		debondingDelegationKeyFmt.Encode(),
		nil,
		true,
		func(key, value []byte) bool {
			var escrowID signature.PublicKey
			var delegatorID signature.PublicKey
			if !debondingDelegationKeyFmt.Decode(key, &delegatorID, &escrowID) {
				return true
			}

			var deb staking.DebondingDelegation
			if err := cbor.Unmarshal(value, &deb); err != nil {
				panic("staking: corrupt debonding delegation state: " + err.Error())
			}

			if delegations[escrowID] == nil {
				delegations[escrowID] = make(map[signature.PublicKey][]*staking.DebondingDelegation)
			}
			delegations[escrowID][delegatorID] = append(delegations[escrowID][delegatorID], &deb)

			return false
		},
	)

	return delegations, nil
}

func (s *ImmutableState) DebondingDelegationsFor(delegatorID signature.PublicKey) (map[signature.PublicKey][]*staking.DebondingDelegation, error) {
	delegations := make(map[signature.PublicKey][]*staking.DebondingDelegation)
	s.Snapshot.IterateRange(
		debondingDelegationKeyFmt.Encode(&delegatorID),
		nil,
		true,
		func(key, value []byte) bool {
			var escrowID signature.PublicKey
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
	params, err := s.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	return params.Slashing, nil
}

func (s *ImmutableState) LastBlockFees() (*quantity.Quantity, error) {
	_, value := s.Snapshot.Get(lastBlockFeesKeyFmt.Encode())
	if value == nil {
		return &quantity.Quantity{}, nil
	}

	var q quantity.Quantity
	if err := cbor.Unmarshal(value, &q); err != nil {
		return nil, err
	}

	return &q, nil
}

type EpochSigning struct {
	Total    uint64
	ByEntity map[signature.PublicKey]uint64
}

func (es *EpochSigning) Update(signingEntities []signature.PublicKey) error {
	oldTotal := es.Total
	es.Total = oldTotal + 1
	if es.Total <= oldTotal {
		return fmt.Errorf("incrementing total blocks count: overflow, old_total=%d", oldTotal)
	}

	for _, entityID := range signingEntities {
		oldCount := es.ByEntity[entityID]
		es.ByEntity[entityID] = oldCount + 1
		if es.ByEntity[entityID] <= oldCount {
			return fmt.Errorf("incrementing count for entity %s: overflow, old_count=%d", entityID, oldCount)
		}
	}

	return nil
}

func (es *EpochSigning) EligibleEntities(thresholdNumerator, thresholdDenominator uint64) ([]signature.PublicKey, error) {
	var eligibleEntities []signature.PublicKey
	if es.Total > math.MaxUint64/thresholdNumerator {
		return nil, fmt.Errorf("overflow in total blocks, total=%d", es.Total)
	}
	thresholdPremultiplied := es.Total * thresholdNumerator
	for entityID, count := range es.ByEntity {
		if count > math.MaxUint64/thresholdDenominator {
			return nil, fmt.Errorf("entity %s: overflow in threshold comparison, count=%d", entityID, count)
		}
		if count*thresholdDenominator < thresholdPremultiplied {
			continue
		}
		eligibleEntities = append(eligibleEntities, entityID)
	}
	sort.Slice(eligibleEntities, func(i, j int) bool {
		return bytes.Compare(eligibleEntities[i][:], eligibleEntities[j][:]) < 0
	})
	return eligibleEntities, nil
}

func (s *ImmutableState) EpochSigning() (*EpochSigning, error) {
	_, value := s.Snapshot.Get(epochSigningKeyFmt.Encode())
	if value == nil {
		// Not present means zero everything.
		return &EpochSigning{
			ByEntity: make(map[signature.PublicKey]uint64),
		}, nil
	}

	var es EpochSigning
	if err := cbor.Unmarshal(value, &es); err != nil {
		return nil, err
	}

	return &es, nil
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

func (s *MutableState) SetTotalSupply(q *quantity.Quantity) {
	s.tree.Set(totalSupplyKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) SetCommonPool(q *quantity.Quantity) {
	s.tree.Set(commonPoolKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) SetConsensusParameters(params *staking.ConsensusParameters) {
	s.tree.Set(parametersKeyFmt.Encode(), cbor.Marshal(params))
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

func (s *MutableState) SetLastBlockFees(q *quantity.Quantity) {
	s.tree.Set(lastBlockFeesKeyFmt.Encode(), cbor.Marshal(q))
}

func (s *MutableState) SetEpochSigning(es *EpochSigning) {
	s.tree.Set(epochSigningKeyFmt.Encode(), cbor.Marshal(es))
}

func (s *MutableState) ClearEpochSigning() {
	s.tree.Remove(epochSigningKeyFmt.Encode())
}

func slashPool(dst *quantity.Quantity, p *staking.SharePool, amount, total *quantity.Quantity) error {
	// slashAmount = amount * p.Balance / total
	slashAmount := p.Balance.Clone()
	if err := slashAmount.Mul(amount); err != nil {
		return errors.Wrap(err, "slashAmount.Mul")
	}
	if err := slashAmount.Quo(total); err != nil {
		return errors.Wrap(err, "slashAmount.Quo")
	}

	if _, err := quantity.MoveUpTo(dst, &p.Balance, slashAmount); err != nil {
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
func (s *MutableState) SlashEscrow(ctx *abci.Context, fromID signature.PublicKey, amount *quantity.Quantity) (bool, error) {
	commonPool, err := s.CommonPool()
	if err != nil {
		return false, fmt.Errorf("staking: failed to query common pool for slash: %w", err)
	}

	from := s.Account(fromID)

	// Compute the amount we need to slash each pool. The amount is split
	// between the pools based on relative total balance.
	total := from.Escrow.Active.Balance.Clone()
	if err = total.Add(&from.Escrow.Debonding.Balance); err != nil {
		return false, fmt.Errorf("staking: compute total balance: %w", err)
	}

	var slashed quantity.Quantity
	if err = slashPool(&slashed, &from.Escrow.Active, amount, total); err != nil {
		return false, errors.Wrap(err, "slashing active escrow")
	}
	if err = slashPool(&slashed, &from.Escrow.Debonding, amount, total); err != nil {
		return false, errors.Wrap(err, "slashing debonding escrow")
	}

	if slashed.IsZero() {
		return false, nil
	}

	totalSlashed := slashed.Clone()

	if err = quantity.Move(commonPool, &slashed, totalSlashed); err != nil {
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
func (s *MutableState) TransferFromCommon(ctx *abci.Context, toID signature.PublicKey, amount *quantity.Quantity) (bool, error) {
	commonPool, err := s.CommonPool()
	if err != nil {
		return false, errors.Wrap(err, "staking: failed to query common pool for transfer")
	}

	to := s.Account(toID)
	transfered, err := quantity.MoveUpTo(&to.General.Balance, commonPool, amount)
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

// AddRewards computes and transfers the staking rewards to active escrow accounts.
// If an error occurs, the pool and affected accounts are left in an invalid state.
// This may fail due to the common pool running out of tokens. In this case, the
// returned error's cause will be `staking.ErrInsufficientBalance`, and it should
// be safe for the caller to roll back to an earlier state tree and continue from
// there.
func (s *MutableState) AddRewards(time epochtime.EpochTime, factor *quantity.Quantity, accounts []signature.PublicKey) error {
	steps, err := s.RewardSchedule()
	if err != nil {
		return err
	}
	var activeStep *staking.RewardStep
	for _, step := range steps {
		if time < step.Until {
			activeStep = &step
			break
		}
	}
	if activeStep == nil {
		// We're past the end of the schedule.
		return nil
	}

	commonPool, err := s.CommonPool()
	if err != nil {
		return errors.Wrap(err, "loading common pool")
	}

	for _, id := range accounts {
		ent := s.Account(id)

		q := ent.Escrow.Active.Balance.Clone()
		// Multiply first.
		if err := q.Mul(factor); err != nil {
			return errors.Wrap(err, "multiplying by reward factor")
		}
		if err := q.Mul(&activeStep.Scale); err != nil {
			return errors.Wrap(err, "multiplying by reward step scale")
		}
		if err := q.Quo(staking.RewardAmountDenominator); err != nil {
			return errors.Wrap(err, "dividing by reward amount denominator")
		}

		if q.IsZero() {
			continue
		}

		var com *quantity.Quantity
		rate := ent.Escrow.CommissionSchedule.CurrentRate(time)
		if rate != nil {
			com = q.Clone()
			// Multiply first.
			if err := com.Mul(rate); err != nil {
				return errors.Wrap(err, "multiplying by commission rate")
			}
			if err := com.Quo(staking.CommissionRateDenominator); err != nil {
				return errors.Wrap(err, "dividing by commission rate denominator")
			}

			if err := q.Sub(com); err != nil {
				return errors.Wrap(err, "subtracting commission")
			}
		}

		if !q.IsZero() {
			if err := quantity.Move(&ent.Escrow.Active.Balance, commonPool, q); err != nil {
				return errors.Wrap(err, "transferring to active escrow balance from common pool")
			}
		}

		if com != nil && !com.IsZero() {
			delegation := s.Delegation(id, id)

			if err := ent.Escrow.Active.Deposit(&delegation.Shares, commonPool, com); err != nil {
				return errors.Wrap(err, "depositing commission")
			}

			s.SetDelegation(id, id, delegation)
		}

		s.SetAccount(id, ent)
	}

	s.SetCommonPool(commonPool)

	return nil
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

		totalSupply, err := s.TotalSupply()
		if err != nil {
			return nil, errors.Wrap(err, "TotalSupply")
		}
		account := s.Account(message.StakingGeneralAdjustmentRoothashMessage.Account)

		switch message.StakingGeneralAdjustmentRoothashMessage.Op {
		case block.Increase:
			err = account.General.Balance.Add(message.StakingGeneralAdjustmentRoothashMessage.Amount)
			if err != nil {
				return errors.Wrapf(err, "couldn't apply adjustment in staking general adjustment message"), nil
			}
			err = totalSupply.Add(message.StakingGeneralAdjustmentRoothashMessage.Amount)
			if err != nil {
				return errors.Wrapf(err, "couldn't adjust total supply in staking general adjustment message"), nil
			}
		case block.Decrease:
			err = account.General.Balance.Sub(message.StakingGeneralAdjustmentRoothashMessage.Amount)
			if err != nil {
				return errors.Wrapf(err, "couldn't apply adjustment in staking general adjustment message"), nil
			}
			err = totalSupply.Sub(message.StakingGeneralAdjustmentRoothashMessage.Amount)
			if err != nil {
				return errors.Wrapf(err, "couldn't adjust total supply in staking general adjustment message"), nil
			}
		default:
			return errors.Errorf("staking general adjustment message has invalid op"), nil
		}

		s.SetTotalSupply(totalSupply)
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
