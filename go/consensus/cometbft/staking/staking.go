// Package staking implements the CometBFT backed staking backend.
package staking

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

// ServiceClient is the scheduler service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	logger *logging.Logger

	consensus  consensus.Backend
	querier    QueryFactory
	descriptor *tmapi.ServiceDescriptor

	eventNotifier *pubsub.Broker
}

// New constructs a new CometBFT backed staking service client.
func New(consensus consensus.Backend, querier QueryFactory) *ServiceClient {
	descriptor := tmapi.NewServiceDescriptor(api.ModuleName, app.EventType, 1)
	descriptor.AddQuery(app.QueryApp)

	return &ServiceClient{
		logger:        logging.GetLogger("cometbft/staking"),
		consensus:     consensus,
		querier:       querier,
		descriptor:    descriptor,
		eventNotifier: pubsub.NewBroker(false),
	}
}

func (sc *ServiceClient) TokenSymbol(ctx context.Context, height int64) (string, error) {
	params, err := sc.ConsensusParameters(ctx, height)
	if err != nil {
		return "", err
	}

	if params.TokenSymbol != "" {
		return params.TokenSymbol, nil
	}

	// Fallback to genesis document.
	genesis, err := sc.consensus.GetGenesisDocument(ctx)
	if err != nil {
		return "", err
	}

	return genesis.Staking.TokenSymbol, nil
}

func (sc *ServiceClient) TokenValueExponent(ctx context.Context, height int64) (uint8, error) {
	params, err := sc.ConsensusParameters(ctx, height)
	if err != nil {
		return 0, err
	}

	if params.TokenValueExponent > 0 {
		return params.TokenValueExponent, nil
	}

	// Fallback to genesis document.
	genesis, err := sc.consensus.GetGenesisDocument(ctx)
	if err != nil {
		return 0, err
	}

	return genesis.Staking.TokenValueExponent, nil
}

func (sc *ServiceClient) TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.TotalSupply(ctx)
}

func (sc *ServiceClient) CommonPool(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.CommonPool(ctx)
}

func (sc *ServiceClient) LastBlockFees(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LastBlockFees(ctx)
}

func (sc *ServiceClient) GovernanceDeposits(ctx context.Context, height int64) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.GovernanceDeposits(ctx)
}

func (sc *ServiceClient) Threshold(ctx context.Context, query *api.ThresholdQuery) (*quantity.Quantity, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Threshold(ctx, query.Kind)
}

func (sc *ServiceClient) Addresses(ctx context.Context, height int64) ([]api.Address, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Addresses(ctx)
}

func (sc *ServiceClient) CommissionScheduleAddresses(ctx context.Context, height int64) ([]api.Address, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.CommissionScheduleAddresses(ctx)
}

func (sc *ServiceClient) Account(ctx context.Context, query *api.OwnerQuery) (*api.Account, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.Account(ctx, query.Owner)
}

func (sc *ServiceClient) DelegationsFor(ctx context.Context, query *api.OwnerQuery) (map[api.Address]*api.Delegation, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DelegationsFor(ctx, query.Owner)
}

func (sc *ServiceClient) DelegationInfosFor(ctx context.Context, query *api.OwnerQuery) (map[api.Address]*api.DelegationInfo, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DelegationInfosFor(ctx, query.Owner)
}

func (sc *ServiceClient) DelegationsTo(ctx context.Context, query *api.OwnerQuery) (map[api.Address]*api.Delegation, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DelegationsTo(ctx, query.Owner)
}

func (sc *ServiceClient) DebondingDelegationsFor(ctx context.Context, query *api.OwnerQuery) (map[api.Address][]*api.DebondingDelegation, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DebondingDelegationsFor(ctx, query.Owner)
}

func (sc *ServiceClient) DebondingDelegationInfosFor(ctx context.Context, query *api.OwnerQuery) (map[api.Address][]*api.DebondingDelegationInfo, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DebondingDelegationInfosFor(ctx, query.Owner)
}

func (sc *ServiceClient) DebondingDelegationsTo(ctx context.Context, query *api.OwnerQuery) (map[api.Address][]*api.DebondingDelegation, error) {
	q, err := sc.querier.QueryAt(ctx, query.Height)
	if err != nil {
		return nil, err
	}

	return q.DebondingDelegationsTo(ctx, query.Owner)
}

func (sc *ServiceClient) Allowance(ctx context.Context, query *api.AllowanceQuery) (*quantity.Quantity, error) {
	acct, err := sc.Account(ctx, &api.OwnerQuery{
		Height: query.Height,
		Owner:  query.Owner,
	})
	if err != nil {
		return nil, err
	}

	allowance := acct.General.Allowances[query.Beneficiary]
	return &allowance, nil
}

func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	// Query the staking genesis state.
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}
	genesis, err := q.Genesis(ctx)
	if err != nil {
		return nil, err
	}

	// Add static values to the genesis document.
	genesis.TokenSymbol, err = sc.TokenSymbol(ctx, height)
	if err != nil {
		return nil, err
	}
	genesis.TokenValueExponent, err = sc.TokenValueExponent(ctx, height)
	if err != nil {
		return nil, err
	}

	return genesis, nil
}

func (sc *ServiceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	results, err := tmapi.GetBlockResults(ctx, height, sc.consensus)
	if err != nil {
		sc.logger.Error("failed to get block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results (at the beginning of the block).
	blockEvs, err := EventsFromCometBFT(results.Height, results.Meta.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for _, txResult := range results.Meta.TxsResults {
		evs, txErr := EventsFromCometBFT(results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, evs...)
	}

	// Decode events from block results (at the end of the block).
	blockEvs, err = EventsFromCometBFT(results.Height, results.Meta.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	return events, nil
}

func (sc *ServiceClient) WatchEvents(context.Context) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	ch := make(chan *api.Event)
	sub := sc.eventNotifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

// ServiceDescriptor implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() *tmapi.ServiceDescriptor {
	return sc.descriptor
}

// DeliverEvent implements api.ServiceClient.
func (sc *ServiceClient) DeliverEvent(_ context.Context, height int64, ev *cmtabcitypes.Event) error {
	events, err := EventsFromCometBFT(height, []cmtabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("staking: failed to process cometbft events: %w", err)
	}

	// Notify subscribers of events.
	for _, ev := range events {
		sc.eventNotifier.Broadcast(ev)
	}

	return nil
}
