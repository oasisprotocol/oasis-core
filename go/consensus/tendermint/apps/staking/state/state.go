package state

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var (
	// AppName is the ABCI application name.
	AppName = "100_staking"
	// KeyAddEscrow is an ABCI event attribute key for AddEscrow calls
	// (value is an api.AddEscrowEvent).
	KeyAddEscrow = []byte("add_escrow")
	// KeyTakeEscrow is an ABCI event attribute key for TakeEscrow calls
	// (value is an app.TakeEscrowEvent).
	KeyTakeEscrow = []byte("take_escrow")
	// KeyTransfer is an ABCI event attribute key for Transfers (value is
	// an app.TransferEvent).
	KeyTransfer = []byte("transfer")

	// accountKeyFmt is the key format used for accounts (account addresses).
	//
	// Value is a CBOR-serialized account address.
	accountKeyFmt = keyformat.New(0x50, &staking.Address{})
	// totalSupplyKeyFmt is the key format used for the total supply.
	//
	// Value is a CBOR-serialized quantity.
	totalSupplyKeyFmt = keyformat.New(0x51)
	// commonPoolKeyFmt is the key format used for the common pool balance.
	//
	// Value is a CBOR-serialized quantity.
	commonPoolKeyFmt = keyformat.New(0x52)
	// delegationKeyFmt is the key format used for delegations (escrow address,
	// delegator address).
	//
	// Value is CBOR-serialized delegation.
	delegationKeyFmt = keyformat.New(0x53, &staking.Address{}, &staking.Address{})
	// debondingDelegationKeyFmt is the key format used for debonding delegations
	// (delegator address, escrow address, seq no).
	//
	// Value is CBOR-serialized debonding delegation.
	debondingDelegationKeyFmt = keyformat.New(0x54, &staking.Address{}, &staking.Address{}, uint64(0))
	// debondingQueueKeyFmt is the debonding queue key format (epoch,
	// delegator address, escrow address, seq no).
	//
	// Value is empty.
	debondingQueueKeyFmt = keyformat.New(0x55, uint64(0), &staking.Address{}, &staking.Address{}, uint64(0))
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
	// governanceDepositsKeyFmt is the key format used for the governance deposits balance.
	//
	// Value is a CBOR-serialized quantity.
	governanceDepositsKeyFmt = keyformat.New(0x59)

	logger = logging.GetLogger("tendermint/staking")
)

// ImmutableState is the immutable staking state wrapper.
type ImmutableState struct {
	is *abciAPI.ImmutableState
}

func (s *ImmutableState) loadStoredBalance(ctx context.Context, key *keyformat.KeyFormat) (*quantity.Quantity, error) {
	value, err := s.is.Get(ctx, key.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if value == nil {
		return &quantity.Quantity{}, nil
	}

	var q quantity.Quantity
	if err = cbor.Unmarshal(value, &q); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &q, nil
}

func (s *ImmutableState) TotalSupply(ctx context.Context) (*quantity.Quantity, error) {
	return s.loadStoredBalance(ctx, totalSupplyKeyFmt)
}

// CommonPool returns the balance of the global common pool.
func (s *ImmutableState) CommonPool(ctx context.Context) (*quantity.Quantity, error) {
	return s.loadStoredBalance(ctx, commonPoolKeyFmt)
}

func (s *ImmutableState) ConsensusParameters(ctx context.Context) (*staking.ConsensusParameters, error) {
	raw, err := s.is.Get(ctx, parametersKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if raw == nil {
		return nil, fmt.Errorf("tendermint/staking: expected consensus parameters to be present in app state")
	}

	var params staking.ConsensusParameters
	if err = cbor.Unmarshal(raw, &params); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &params, nil
}

func (s *ImmutableState) DebondingInterval(ctx context.Context) (epochtime.EpochTime, error) {
	params, err := s.ConsensusParameters(ctx)
	if err != nil {
		return epochtime.EpochInvalid, err
	}

	return params.DebondingInterval, nil
}

func (s *ImmutableState) RewardSchedule(ctx context.Context) ([]staking.RewardStep, error) {
	params, err := s.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	return params.RewardSchedule, nil
}

func (s *ImmutableState) CommissionScheduleRules(ctx context.Context) (*staking.CommissionScheduleRules, error) {
	params, err := s.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	return &params.CommissionScheduleRules, nil
}

// Thresholds returns the currently configured thresholds if any.
func (s *ImmutableState) Thresholds(ctx context.Context) (map[staking.ThresholdKind]quantity.Quantity, error) {
	params, err := s.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	return params.Thresholds, nil
}

func (s *ImmutableState) Addresses(ctx context.Context) ([]staking.Address, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var addresses []staking.Address
	for it.Seek(accountKeyFmt.Encode()); it.Valid(); it.Next() {
		var addr staking.Address
		if !accountKeyFmt.Decode(it.Key(), &addr) {
			break
		}

		addresses = append(addresses, addr)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return addresses, nil
}

// Account returns the staking account for the given account address.
func (s *ImmutableState) Account(ctx context.Context, address staking.Address) (*staking.Account, error) {
	if !address.IsValid() {
		return nil, fmt.Errorf("tendermint/staking: invalid account address: %s", address)
	}

	value, err := s.is.Get(ctx, accountKeyFmt.Encode(&address))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if value == nil {
		return &staking.Account{}, nil
	}

	var ent staking.Account
	if err = cbor.Unmarshal(value, &ent); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &ent, nil
}

// EscrowBalance returns the escrow balance for the given account address.
func (s *ImmutableState) EscrowBalance(ctx context.Context, address staking.Address) (*quantity.Quantity, error) {
	account, err := s.Account(ctx, address)
	if err != nil {
		return nil, err
	}
	return &account.Escrow.Active.Balance, nil
}

func (s *ImmutableState) Delegations(
	ctx context.Context,
) (map[staking.Address]map[staking.Address]*staking.Delegation, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	delegations := make(map[staking.Address]map[staking.Address]*staking.Delegation)
	for it.Seek(delegationKeyFmt.Encode()); it.Valid(); it.Next() {
		var escrowAddr staking.Address
		var delegatorAddr staking.Address
		if !delegationKeyFmt.Decode(it.Key(), &escrowAddr, &delegatorAddr) {
			break
		}

		var del staking.Delegation
		if err := cbor.Unmarshal(it.Value(), &del); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		if delegations[escrowAddr] == nil {
			delegations[escrowAddr] = make(map[staking.Address]*staking.Delegation)
		}
		delegations[escrowAddr][delegatorAddr] = &del
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return delegations, nil
}

func (s *ImmutableState) Delegation(
	ctx context.Context,
	delegatorAddr, escrowAddr staking.Address,
) (*staking.Delegation, error) {
	value, err := s.is.Get(ctx, delegationKeyFmt.Encode(&escrowAddr, &delegatorAddr))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if value == nil {
		return &staking.Delegation{}, nil
	}

	var del staking.Delegation
	if err = cbor.Unmarshal(value, &del); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &del, nil
}

func (s *ImmutableState) DelegationsFor(
	ctx context.Context,
	delegatorAddr staking.Address,
) (map[staking.Address]*staking.Delegation, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	delegations := make(map[staking.Address]*staking.Delegation)
	for it.Seek(delegationKeyFmt.Encode()); it.Valid(); it.Next() {
		var escrowAddr staking.Address
		var decDelegatorAddr staking.Address
		if !delegationKeyFmt.Decode(it.Key(), &escrowAddr, &decDelegatorAddr) {
			break
		}
		if !decDelegatorAddr.Equal(delegatorAddr) {
			continue
		}

		var del staking.Delegation
		if err := cbor.Unmarshal(it.Value(), &del); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		delegations[escrowAddr] = &del
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return delegations, nil
}

func (s *ImmutableState) DebondingDelegations(
	ctx context.Context,
) (map[staking.Address]map[staking.Address][]*staking.DebondingDelegation, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	delegations := make(map[staking.Address]map[staking.Address][]*staking.DebondingDelegation)
	for it.Seek(debondingDelegationKeyFmt.Encode()); it.Valid(); it.Next() {
		var escrowAddr staking.Address
		var delegatorAddr staking.Address
		if !debondingDelegationKeyFmt.Decode(it.Key(), &delegatorAddr, &escrowAddr) {
			break
		}

		var deb staking.DebondingDelegation
		if err := cbor.Unmarshal(it.Value(), &deb); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		if delegations[escrowAddr] == nil {
			delegations[escrowAddr] = make(map[staking.Address][]*staking.DebondingDelegation)
		}
		delegations[escrowAddr][delegatorAddr] = append(delegations[escrowAddr][delegatorAddr], &deb)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return delegations, nil
}

func (s *ImmutableState) DebondingDelegationsFor(
	ctx context.Context,
	delegatorAddr staking.Address,
) (map[staking.Address][]*staking.DebondingDelegation, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	delegations := make(map[staking.Address][]*staking.DebondingDelegation)
	for it.Seek(debondingDelegationKeyFmt.Encode(&delegatorAddr)); it.Valid(); it.Next() {
		var escrowAddr staking.Address
		var decDelegatorAddr staking.Address
		if !debondingDelegationKeyFmt.Decode(it.Key(), &decDelegatorAddr, &escrowAddr) {
			break
		}
		if !decDelegatorAddr.Equal(delegatorAddr) {
			continue
		}

		var deb staking.DebondingDelegation
		if err := cbor.Unmarshal(it.Value(), &deb); err != nil {
			return nil, abciAPI.UnavailableStateError(err)
		}

		delegations[escrowAddr] = append(delegations[escrowAddr], &deb)
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return delegations, nil
}

func (s *ImmutableState) DebondingDelegation(
	ctx context.Context,
	delegatorAddr, escrowAddr staking.Address,
	seq uint64,
) (*staking.DebondingDelegation, error) {
	value, err := s.is.Get(ctx, debondingDelegationKeyFmt.Encode(&delegatorAddr, &escrowAddr, seq))
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if value == nil {
		return &staking.DebondingDelegation{}, nil
	}

	var deb staking.DebondingDelegation
	if err = cbor.Unmarshal(value, &deb); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &deb, nil
}

type DebondingQueueEntry struct {
	Epoch         epochtime.EpochTime
	DelegatorAddr staking.Address
	EscrowAddr    staking.Address
	Seq           uint64
	Delegation    *staking.DebondingDelegation
}

func (s *ImmutableState) ExpiredDebondingQueue(ctx context.Context, epoch epochtime.EpochTime) ([]*DebondingQueueEntry, error) {
	it := s.is.NewIterator(ctx)
	defer it.Close()

	var entries []*DebondingQueueEntry
	for it.Seek(debondingQueueKeyFmt.Encode()); it.Valid(); it.Next() {
		var decEpoch, seq uint64
		var escrowAddr staking.Address
		var delegatorAddr staking.Address
		if !debondingQueueKeyFmt.Decode(it.Key(), &decEpoch, &delegatorAddr, &escrowAddr, &seq) || decEpoch > uint64(epoch) {
			break
		}

		deb, err := s.DebondingDelegation(ctx, delegatorAddr, escrowAddr, seq)
		if err != nil {
			return nil, err
		}
		entries = append(entries, &DebondingQueueEntry{
			Epoch:         epochtime.EpochTime(decEpoch),
			DelegatorAddr: delegatorAddr,
			EscrowAddr:    escrowAddr,
			Seq:           seq,
			Delegation:    deb,
		})
	}
	if it.Err() != nil {
		return nil, abciAPI.UnavailableStateError(it.Err())
	}
	return entries, nil
}

func (s *ImmutableState) Slashing(ctx context.Context) (map[staking.SlashReason]staking.Slash, error) {
	params, err := s.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	return params.Slashing, nil
}

func (s *ImmutableState) LastBlockFees(ctx context.Context) (*quantity.Quantity, error) {
	return s.loadStoredBalance(ctx, lastBlockFeesKeyFmt)
}

func (s *ImmutableState) GovernanceDeposits(ctx context.Context) (*quantity.Quantity, error) {
	return s.loadStoredBalance(ctx, governanceDepositsKeyFmt)
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

func (s *ImmutableState) EpochSigning(ctx context.Context) (*EpochSigning, error) {
	value, err := s.is.Get(ctx, epochSigningKeyFmt.Encode())
	if err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	if value == nil {
		// Not present means zero everything.
		return &EpochSigning{
			ByEntity: make(map[signature.PublicKey]uint64),
		}, nil
	}

	var es EpochSigning
	if err = cbor.Unmarshal(value, &es); err != nil {
		return nil, abciAPI.UnavailableStateError(err)
	}
	return &es, nil
}

func NewImmutableState(ctx context.Context, state abciAPI.ApplicationQueryState, version int64) (*ImmutableState, error) {
	is, err := abciAPI.NewImmutableState(ctx, state, version)
	if err != nil {
		return nil, err
	}

	return &ImmutableState{is}, nil
}

// MutableState is a mutable staking state wrapper.
type MutableState struct {
	*ImmutableState

	ms mkvs.KeyValueTree
}

func (s *MutableState) SetAccount(ctx context.Context, addr staking.Address, account *staking.Account) error {
	err := s.ms.Insert(ctx, accountKeyFmt.Encode(&addr), cbor.Marshal(account))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetTotalSupply(ctx context.Context, q *quantity.Quantity) error {
	err := s.ms.Insert(ctx, totalSupplyKeyFmt.Encode(), cbor.Marshal(q))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetCommonPool(ctx context.Context, q *quantity.Quantity) error {
	err := s.ms.Insert(ctx, commonPoolKeyFmt.Encode(), cbor.Marshal(q))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetConsensusParameters(ctx context.Context, params *staking.ConsensusParameters) error {
	err := s.ms.Insert(ctx, parametersKeyFmt.Encode(), cbor.Marshal(params))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetDelegation(
	ctx context.Context,
	delegatorAddr, escrowAddr staking.Address,
	d *staking.Delegation,
) error {
	// Remove delegation if there are no more shares in it.
	if d.Shares.IsZero() {
		err := s.ms.Remove(ctx, delegationKeyFmt.Encode(&escrowAddr, &delegatorAddr))
		return abciAPI.UnavailableStateError(err)
	}

	err := s.ms.Insert(ctx, delegationKeyFmt.Encode(&escrowAddr, &delegatorAddr), cbor.Marshal(d))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetDebondingDelegation(
	ctx context.Context,
	delegatorAddr, escrowAddr staking.Address,
	seq uint64,
	d *staking.DebondingDelegation,
) error {
	key := debondingDelegationKeyFmt.Encode(&delegatorAddr, &escrowAddr, seq)

	if d == nil {
		// Remove descriptor.
		err := s.ms.Remove(ctx, key)
		return abciAPI.UnavailableStateError(err)
	}

	// Add to debonding queue.
	if err := s.ms.Insert(
		ctx,
		debondingQueueKeyFmt.Encode(uint64(d.DebondEndTime),
			&delegatorAddr,
			&escrowAddr,
			seq,
		),
		[]byte{},
	); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	// Add descriptor.
	if err := s.ms.Insert(ctx, key, cbor.Marshal(d)); err != nil {
		return abciAPI.UnavailableStateError(err)
	}
	return nil
}

func (s *MutableState) RemoveFromDebondingQueue(
	ctx context.Context,
	epoch epochtime.EpochTime,
	delegatorAddr, escrowAddr staking.Address,
	seq uint64,
) error {
	err := s.ms.Remove(ctx, debondingQueueKeyFmt.Encode(uint64(epoch), &delegatorAddr, &escrowAddr, seq))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetLastBlockFees(ctx context.Context, q *quantity.Quantity) error {
	err := s.ms.Insert(ctx, lastBlockFeesKeyFmt.Encode(), cbor.Marshal(q))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetEpochSigning(ctx context.Context, es *EpochSigning) error {
	err := s.ms.Insert(ctx, epochSigningKeyFmt.Encode(), cbor.Marshal(es))
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) ClearEpochSigning(ctx context.Context) error {
	err := s.ms.Remove(ctx, epochSigningKeyFmt.Encode())
	return abciAPI.UnavailableStateError(err)
}

func (s *MutableState) SetGovernanceDeposits(ctx context.Context, q *quantity.Quantity) error {
	err := s.ms.Insert(ctx, governanceDepositsKeyFmt.Encode(), cbor.Marshal(q))
	return abciAPI.UnavailableStateError(err)
}

func slashPool(dst *quantity.Quantity, p *staking.SharePool, amount, total *quantity.Quantity) error {
	// slashAmount = amount * p.Balance / total
	slashAmount := p.Balance.Clone()
	if err := slashAmount.Mul(amount); err != nil {
		return fmt.Errorf("tendermint/staking: slashAmount.Mul: %w", err)
	}
	if err := slashAmount.Quo(total); err != nil {
		return fmt.Errorf("tendermint/staking: slashAmount.Quo: %w", err)
	}

	if _, err := quantity.MoveUpTo(dst, &p.Balance, slashAmount); err != nil {
		return fmt.Errorf("tendermint/staking: failed moving stake: %w", err)
	}

	return nil
}

// SlashEscrow slashes the escrow balance and the escrow-but-undergoing-debonding
// balance of the account, transferring it to the global common pool, returning
// true iff the amount actually slashed is > 0.
//
// WARNING: This is an internal routine to be used to implement staking policy,
// and MUST NOT be exposed outside of backend implementations.
func (s *MutableState) SlashEscrow(
	ctx *abciAPI.Context,
	fromAddr staking.Address,
	amount *quantity.Quantity,
) (bool, error) {
	commonPool, err := s.CommonPool(ctx)
	if err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to query common pool for slash: %w", err)
	}

	from, err := s.Account(ctx, fromAddr)
	if err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to query account %s: %w", fromAddr, err)
	}

	// Compute the amount we need to slash each pool. The amount is split
	// between the pools based on relative total balance.
	total := from.Escrow.Active.Balance.Clone()
	if err = total.Add(&from.Escrow.Debonding.Balance); err != nil {
		return false, fmt.Errorf("tendermint/staking: compute total balance: %w", err)
	}

	var slashed quantity.Quantity
	if err = slashPool(&slashed, &from.Escrow.Active, amount, total); err != nil {
		return false, fmt.Errorf("tendermint/staking: failed slashing active escrow: %w", err)
	}
	if err = slashPool(&slashed, &from.Escrow.Debonding, amount, total); err != nil {
		return false, fmt.Errorf("tendermint/staking: failed slashing debonding escrow: %w", err)
	}

	if slashed.IsZero() {
		return false, nil
	}

	totalSlashed := slashed.Clone()

	if err = quantity.Move(commonPool, &slashed, totalSlashed); err != nil {
		return false, fmt.Errorf("tendermint/staking: failed moving stake to common pool: %w", err)
	}

	if err = s.SetCommonPool(ctx, commonPool); err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to set common pool: %w", err)
	}
	if err = s.SetAccount(ctx, fromAddr, from); err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to set account. %w", err)
	}

	if !ctx.IsCheckOnly() {
		ev := cbor.Marshal(&staking.TakeEscrowEvent{
			Owner:  fromAddr,
			Amount: *totalSlashed,
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
func (s *MutableState) TransferFromCommon(
	ctx *abciAPI.Context,
	toAddr staking.Address,
	amount *quantity.Quantity,
) (bool, error) {
	commonPool, err := s.CommonPool(ctx)
	if err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to query common pool for transfer: %w", err)
	}

	to, err := s.Account(ctx, toAddr)
	if err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to query account %s: %w", toAddr, err)
	}
	transferred, err := quantity.MoveUpTo(&to.General.Balance, commonPool, amount)
	if err != nil {
		return false, fmt.Errorf("tendermint/staking: failed to transfer from common pool: %w", err)
	}

	ret := !transferred.IsZero()
	if ret {
		if err = s.SetCommonPool(ctx, commonPool); err != nil {
			return false, fmt.Errorf("tendermint/staking: failed to set common pool: %w", err)
		}
		if err = s.SetAccount(ctx, toAddr, to); err != nil {
			return false, fmt.Errorf("tendermint/staking: failed to set account %s: %w", toAddr, err)
		}

		if !ctx.IsCheckOnly() {
			ev := cbor.Marshal(&staking.TransferEvent{
				From:   staking.CommonPoolAddress,
				To:     toAddr,
				Amount: *transferred,
			})
			ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyTransfer, ev))
		}
	}

	return ret, nil
}

// TransferToGovernanceDeposits transfers the amount from the submitter to the
// governance deposits pool.
func (s *MutableState) TransferToGovernanceDeposits(
	ctx *api.Context,
	fromAddr staking.Address,
	amount *quantity.Quantity,
) error {
	from, err := s.Account(ctx, fromAddr)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query account %s: %w", fromAddr, err)
	}

	deposits, err := s.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query governance deposit for deposit %w", err)
	}

	if err = quantity.Move(deposits, &from.General.Balance, amount); err != nil {
		return fmt.Errorf("tendermint/staking: failed to transfer to governance deposits, from: %s: %w", fromAddr, err)
	}

	if err = s.SetAccount(ctx, fromAddr, from); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set governance deposit submitter account: %w", err)
	}
	if err = s.SetGovernanceDeposits(ctx, deposits); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set governance deposits: %w", err)
	}

	if !ctx.IsCheckOnly() {
		ev := cbor.Marshal(&staking.TransferEvent{
			From:   fromAddr,
			To:     staking.GovernanceDepositsAddress,
			Amount: *amount,
		})
		ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyTransfer, ev))
	}

	return nil
}

// TransferFromGovernanceDeposits transfers the amount from the governance
// deposits pool to the specified address.
func (s *MutableState) TransferFromGovernanceDeposits(
	ctx *api.Context,
	toAddr staking.Address,
	amount *quantity.Quantity,
) error {
	to, err := s.Account(ctx, toAddr)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query account %s: %w", toAddr, err)
	}

	deposits, err := s.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query governance deposit %w", err)
	}

	if err = quantity.Move(&to.General.Balance, deposits, amount); err != nil {
		return fmt.Errorf("tendermint/staking: failed to transfer from governance deposits, to: %s: %w", toAddr, err)
	}

	if err = s.SetAccount(ctx, toAddr, to); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set governance deposit submitter account: %w", err)
	}
	if err = s.SetGovernanceDeposits(ctx, deposits); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set governance deposits: %w", err)
	}

	if !ctx.IsCheckOnly() {
		ev := cbor.Marshal(&staking.TransferEvent{
			From:   staking.GovernanceDepositsAddress,
			To:     toAddr,
			Amount: *amount,
		})
		ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyTransfer, ev))
	}

	return nil
}

// DiscardGovernanceDeposit discards the amount from the governance
// deposits pool to the common pool.
func (s *MutableState) DiscardGovernanceDeposit(
	ctx *api.Context,
	amount *quantity.Quantity,
) error {
	commonPool, err := s.CommonPool(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query common pool for transfer: %w", err)
	}

	deposits, err := s.GovernanceDeposits(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query governance deposit %w", err)
	}

	if err = quantity.Move(commonPool, deposits, amount); err != nil {
		return fmt.Errorf("tendermint/staking: failed to transfer from governance deposits, to common pool: %w", err)
	}

	if err = s.SetGovernanceDeposits(ctx, deposits); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set governance deposits: %w", err)
	}
	if err = s.SetCommonPool(ctx, commonPool); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set common pool: %w", err)
	}

	if !ctx.IsCheckOnly() {
		ev := cbor.Marshal(&staking.TransferEvent{
			From:   staking.GovernanceDepositsAddress,
			To:     staking.CommonPoolAddress,
			Amount: *amount,
		})
		ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyTransfer, ev))
	}

	return nil
}

// AddRewards computes and transfers a staking reward to active escrow accounts.
// If an error occurs, the pool and affected accounts are left in an invalid state.
// This may fail due to the common pool running out of stake. In this case, the
// returned error's cause will be `staking.ErrInsufficientBalance`, and it should
// be safe for the caller to roll back to an earlier state tree and continue from
// there.
func (s *MutableState) AddRewards(
	ctx *abciAPI.Context,
	time epochtime.EpochTime,
	factor *quantity.Quantity,
	addresses []staking.Address,
) error {
	steps, err := s.RewardSchedule(ctx)
	if err != nil {
		return err
	}
	var activeStep *staking.RewardStep
	for i, step := range steps {
		if time < step.Until {
			activeStep = &steps[i]
			break
		}
	}
	if activeStep == nil {
		// We're past the end of the schedule.
		return nil
	}

	commonPool, err := s.CommonPool(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/staking: loading common pool: %w", err)
	}

	for _, addr := range addresses {
		var ent *staking.Account
		ent, err = s.Account(ctx, addr)
		if err != nil {
			return fmt.Errorf("tendermint/staking: failed to fetch account %s: %w", addr, err)
		}

		q := ent.Escrow.Active.Balance.Clone()
		// Multiply first.
		if err = q.Mul(factor); err != nil {
			return fmt.Errorf("tendermint/staking: failed multiplying by reward factor: %w", err)
		}
		if err = q.Mul(&activeStep.Scale); err != nil {
			return fmt.Errorf("tendermint/staking: failed multiplying by reward step scale: %w", err)
		}
		if err = q.Quo(staking.RewardAmountDenominator); err != nil {
			return fmt.Errorf("tendermint/staking: failed dividing by reward amount denominator: %w", err)
		}

		if q.IsZero() {
			continue
		}

		var com *quantity.Quantity
		rate := ent.Escrow.CommissionSchedule.CurrentRate(time)
		if rate != nil {
			com = q.Clone()
			// Multiply first.
			if err = com.Mul(rate); err != nil {
				return fmt.Errorf("tendermint/staking: failed multiplying by commission rate: %w", err)
			}
			if err = com.Quo(staking.CommissionRateDenominator); err != nil {
				return fmt.Errorf("tendermint/staking: failed dividing by commission rate denominator: %w", err)
			}

			if err = q.Sub(com); err != nil {
				return fmt.Errorf("tendermint/staking: failed subtracting commission: %w", err)
			}
		}

		if !q.IsZero() {
			if err = quantity.Move(&ent.Escrow.Active.Balance, commonPool, q); err != nil {
				return fmt.Errorf("tendermint/staking: failed transferring to active escrow balance from common pool: %w", err)
			}
			ev := cbor.Marshal(&staking.AddEscrowEvent{
				Owner:  staking.CommonPoolAddress,
				Escrow: addr,
				Amount: *q,
			})
			ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyAddEscrow, ev))
		}

		if com != nil && !com.IsZero() {
			var delegation *staking.Delegation
			delegation, err = s.Delegation(ctx, addr, addr)
			if err != nil {
				return fmt.Errorf("tendermint/staking: failed to query delegation: %w", err)
			}

			if err = ent.Escrow.Active.Deposit(&delegation.Shares, commonPool, com); err != nil {
				return fmt.Errorf("tendermint/staking: depositing commission: %w", err)
			}

			if err = s.SetDelegation(ctx, addr, addr, delegation); err != nil {
				return fmt.Errorf("tendermint/staking: failed to set delegation: %w", err)
			}

			ev := cbor.Marshal(&staking.AddEscrowEvent{
				Owner:  staking.CommonPoolAddress,
				Escrow: addr,
				Amount: *com,
			})
			ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyAddEscrow, ev))
		}

		if err = s.SetAccount(ctx, addr, ent); err != nil {
			return fmt.Errorf("tendermint/staking: failed to set account: %w", err)
		}
	}

	if err = s.SetCommonPool(ctx, commonPool); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set common pool: %w", err)
	}

	return nil
}

// AddRewardSingleAttenuated computes, scales, and transfers a staking reward to an active escrow account.
func (s *MutableState) AddRewardSingleAttenuated(
	ctx *abciAPI.Context,
	time epochtime.EpochTime,
	factor *quantity.Quantity,
	attenuationNumerator, attenuationDenominator int,
	address staking.Address,
) error {
	steps, err := s.RewardSchedule(ctx)
	if err != nil {
		return fmt.Errorf("failed to query reward schedule: %w", err)
	}
	var activeStep *staking.RewardStep
	for i, step := range steps {
		if time < step.Until {
			activeStep = &steps[i]
			break
		}
	}
	if activeStep == nil {
		// We're past the end of the schedule.
		return nil
	}

	var numQ, denQ quantity.Quantity
	if err = numQ.FromInt64(int64(attenuationNumerator)); err != nil {
		return fmt.Errorf("tendermint/staking: failed importing attenuation numerator %d: %w", attenuationNumerator, err)
	}
	if err = denQ.FromInt64(int64(attenuationDenominator)); err != nil {
		return fmt.Errorf("tendermint/staking: failed importing attenuation denominator %d: %w", attenuationDenominator, err)
	}

	commonPool, err := s.CommonPool(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed loading common pool: %w", err)
	}

	acct, err := s.Account(ctx, address)
	if err != nil {
		return fmt.Errorf("tendermint/staking: failed to query account %s: %w", address, err)
	}

	q := acct.Escrow.Active.Balance.Clone()
	// Multiply first.
	if err = q.Mul(factor); err != nil {
		return fmt.Errorf("tendermint/staking: failed multiplying by reward factor: %w", err)
	}
	if err = q.Mul(&activeStep.Scale); err != nil {
		return fmt.Errorf("tendermint/staking: failed multiplying by reward step scale: %w", err)
	}
	if err = q.Mul(&numQ); err != nil {
		return fmt.Errorf("tendermint/staking: failed multiplying by attenuation numerator: %w", err)
	}
	if err = q.Quo(staking.RewardAmountDenominator); err != nil {
		return fmt.Errorf("tendermint/staking: failed dividing by reward amount denominator: %w", err)
	}
	if err = q.Quo(&denQ); err != nil {
		return fmt.Errorf("tendermint/staking: failed dividing by attenuation denominator: %w", err)
	}

	if q.IsZero() {
		return nil
	}

	var com *quantity.Quantity
	rate := acct.Escrow.CommissionSchedule.CurrentRate(time)
	if rate != nil {
		com = q.Clone()
		// Multiply first.
		if err = com.Mul(rate); err != nil {
			return fmt.Errorf("tendermint/staking: failed multiplying by commission rate: %w", err)
		}
		if err = com.Quo(staking.CommissionRateDenominator); err != nil {
			return fmt.Errorf("tendermint/staking: failed dividing by commission rate denominator: %w", err)
		}

		if err = q.Sub(com); err != nil {
			return fmt.Errorf("tendermint/staking: failed subtracting commission: %w", err)
		}
	}

	if !q.IsZero() {
		if err = quantity.Move(&acct.Escrow.Active.Balance, commonPool, q); err != nil {
			return fmt.Errorf("tendermint/staking: failed transferring to active escrow balance from common pool: %w", err)
		}
		ev := cbor.Marshal(&staking.AddEscrowEvent{
			Owner:  staking.CommonPoolAddress,
			Escrow: address,
			Amount: *q,
		})
		ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyAddEscrow, ev))
	}

	if com != nil && !com.IsZero() {
		var delegation *staking.Delegation
		delegation, err = s.Delegation(ctx, address, address)
		if err != nil {
			return fmt.Errorf("tendermint/staking: failed to query delegation: %w", err)
		}

		if err = acct.Escrow.Active.Deposit(&delegation.Shares, commonPool, com); err != nil {
			return fmt.Errorf("tendermint/staking: failed depositing commission: %w", err)
		}

		if err = s.SetDelegation(ctx, address, address, delegation); err != nil {
			return fmt.Errorf("tendermint/staking: failed to set delegation: %w", err)
		}

		ev := cbor.Marshal(&staking.AddEscrowEvent{
			Owner:  staking.CommonPoolAddress,
			Escrow: address,
			Amount: *com,
		})
		ctx.EmitEvent(api.NewEventBuilder(AppName).Attribute(KeyAddEscrow, ev))
	}

	if err = s.SetAccount(ctx, address, acct); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set account: %w", err)
	}

	if err = s.SetCommonPool(ctx, commonPool); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set common pool: %w", err)
	}

	return nil
}

// NewMutableState creates a new mutable staking state wrapper.
func NewMutableState(tree mkvs.KeyValueTree) *MutableState {
	return &MutableState{
		ImmutableState: &ImmutableState{
			&abciAPI.ImmutableState{ImmutableKeyValueTree: tree},
		},
		ms: tree,
	}
}
