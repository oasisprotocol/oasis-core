package stateless

import (
	"context"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"golang.org/x/sync/errgroup"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/beacon"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/consensus"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/governance"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/registry"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/roothash"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/scheduler"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/staking"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/vault"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	schedulerAPI "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	vaultAPI "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// Config contains configuration parameters for the stateless services.
type Config struct {
	// ChainID is the unique identifier of the chain.
	ChainID string
	// ChainContext is the chain's domain separation context.
	ChainContext string
	// Genesis provides access to the genesis document.
	Genesis genesisAPI.Provider
	// GenesisDoc is the CometBFT genesis document.
	GenesisDoc *cmttypes.GenesisDoc
	// GenesisHeight is the block height at which the genesis document
	// was generated.
	GenesisHeight int64
	// BaseEpoch is the starting epoch.
	BaseEpoch beaconAPI.EpochTime
	// BaseHeight is the starting height.
	BaseHeight int64
}

// Services is a stateless implementation of CometBFT services.
type Services struct {
	consensus *Core

	beacon     *beacon.ServiceClient
	governance *governance.ServiceClient
	keymanager *keymanager.ServiceClient
	registry   *registry.ServiceClient
	roothash   *roothash.ServiceClient
	scheduler  *scheduler.ServiceClient
	staking    *staking.ServiceClient
	vault      *vault.ServiceClient

	eventFilters map[api.ServiceClient]*full.EventFilter

	synced chan struct{}

	logger *logging.Logger
}

// NewServices creates new stateless CometBFT services.
//
// Stateless services retrieve untrusted data from the specified remote provider
// and verify it using the provided light client.
func NewServices(provider consensusAPI.Backend, lightClient *light.Client, cfg Config) (*Services, error) {
	core := NewCore(provider, lightClient, cfg)
	syncer := provider.State()

	beaconQuerier := beacon.NewLightQueryFactory(core, syncer)
	consensusQuerier := consensus.NewLightQueryFactory(core, syncer)
	governanceQuerier := governance.NewLightQueryFactory(core, syncer)
	secretsQuerier := secrets.NewLightQueryFactory(core, syncer)
	churpQuerier := churp.NewLightQueryFactory(core, syncer)
	registryQuerier := registry.NewLightQueryFactory(core, syncer)
	roothashQuerier := roothash.NewLightQueryFactory(core, syncer)
	schedulerQuerier := scheduler.NewLightQueryFactory(core, syncer)
	stakingQuerier := staking.NewLightQueryFactory(core, syncer)
	vaultQuerier := vault.NewLightQueryFactory(core, syncer)

	beacon := beacon.New(cfg.BaseEpoch, cfg.BaseHeight, core, beaconQuerier)
	governance := governance.New(core, governanceQuerier)
	keymanager := keymanager.New(secretsQuerier, churpQuerier)
	registry := registry.New(core, registryQuerier)
	roothash := roothash.New(core, roothashQuerier)
	scheduler := scheduler.New(schedulerQuerier)
	staking := staking.New(core, stakingQuerier)
	vault := vault.New(core, vaultQuerier)

	core.SetQueriers(beaconQuerier, consensusQuerier, registryQuerier)

	eventFilters := map[api.ServiceClient]*full.EventFilter{
		beacon:     full.NewEventFilter(beacon.ServiceDescriptor().EventType()),
		governance: full.NewEventFilter(governance.ServiceDescriptor().EventType()),
		keymanager: full.NewEventFilter(keymanager.ServiceDescriptor().EventType()),
		registry:   full.NewEventFilter(registry.ServiceDescriptor().EventType()),
		roothash:   full.NewEventFilter(roothash.ServiceDescriptor().EventType()),
		scheduler:  full.NewEventFilter(scheduler.ServiceDescriptor().EventType()),
		staking:    full.NewEventFilter(staking.ServiceDescriptor().EventType()),
		vault:      full.NewEventFilter(vault.ServiceDescriptor().EventType()),
	}

	return &Services{
		beacon:       beacon,
		consensus:    core,
		governance:   governance,
		keymanager:   keymanager,
		registry:     registry,
		roothash:     roothash,
		scheduler:    scheduler,
		staking:      staking,
		vault:        vault,
		eventFilters: eventFilters,
		synced:       make(chan struct{}),
		logger:       logging.GetLogger("cometbft/stateless/services"),
	}, nil
}

// Synced returns a channel that is closed once synchronization is complete.
func (s *Services) Synced() <-chan struct{} {
	return s.synced
}

// Beacon implements consensusAPI.Services.
func (s *Services) Beacon() beaconAPI.Backend {
	return s.beacon
}

// Core implements consensusAPI.Services.
func (s *Services) Core() consensusAPI.Backend {
	return s.consensus
}

// Governance implements consensusAPI.Services.
func (s *Services) Governance() governanceAPI.Backend {
	return s.governance
}

// KeyManager implements consensusAPI.Services.
func (s *Services) KeyManager() keymanagerAPI.Backend {
	return s.keymanager
}

// Registry implements consensusAPI.Services.
func (s *Services) Registry() registryAPI.Backend {
	return s.registry
}

// RootHash implements consensusAPI.Services.
func (s *Services) RootHash() roothashAPI.Backend {
	return s.roothash
}

// Scheduler implements consensusAPI.Services.
func (s *Services) Scheduler() schedulerAPI.Backend {
	return s.scheduler
}

// Staking implements consensusAPI.Services.
func (s *Services) Staking() stakingAPI.Backend {
	return s.staking
}

// Vault implements consensusAPI.Services.
func (s *Services) Vault() vaultAPI.Backend {
	return s.vault
}

// Serve listens for blocks and notifies service clients about new blocks
// and related events.
func (s *Services) Serve(ctx context.Context) error {
	s.logger.Info("started")

	if err := s.serve(ctx); err != nil {
		s.logger.Error("stopped", "err", err)
		return err
	}

	return nil
}

func (s *Services) serve(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := s.consensus.Serve(ctx); err != nil {
			return fmt.Errorf("consensus stopped: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := s.watchBlocks(ctx); err != nil {
			return fmt.Errorf("block watcher stopped: %w", err)
		}
		return nil
	})

	return g.Wait()
}

func (s *Services) watchBlocks(ctx context.Context) error {
	blkCh, blkSub, err := s.consensus.WatchBlocks(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch blocks: %w", err)
	}
	defer blkSub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case blk := <-blkCh:
			if err := s.handleBlock(ctx, blk); err != nil {
				return fmt.Errorf("failed to handle block: %w", err)
			}
		}
	}
}

func (s *Services) handleBlock(ctx context.Context, blk *consensusAPI.Block) error {
	select {
	case <-s.synced:
	default:
		close(s.synced)
	}

	s.logger.Debug("new block", "height", blk.Height)

	txs, err := s.consensus.GetTransactions(ctx, blk.Height)
	if err != nil {
		return fmt.Errorf("failed to get transactions: %w", err)
	}

	results, err := s.consensus.GetBlockResults(ctx, blk.Height)
	if err != nil {
		return fmt.Errorf("failed to get block results: %w", err)
	}

	meta, err := api.NewBlockResultsMeta(results)
	if err != nil {
		return fmt.Errorf("failed to convert block results: %w", err)
	}

	for svc, filter := range s.eventFilters {
		if err := s.deliverHeight(ctx, svc, blk.Height); err != nil {
			return fmt.Errorf("failed to deliver block height: %w", err)
		}

		if err := s.deliverEvents(ctx, svc, filter, blk.Height, txs, meta); err != nil {
			return fmt.Errorf("failed to deliver block events: %w", err)
		}
	}

	return nil
}

func (s *Services) deliverHeight(ctx context.Context, svc api.ServiceClient, height int64) error {
	return svc.DeliverHeight(ctx, height)
}

func (s *Services) deliverEvents(ctx context.Context, svc api.ServiceClient, filter *full.EventFilter, height int64, txs [][]byte, meta *api.BlockResultsMeta) error {
	s.updateEventFilter(svc, filter)

	if len(txs) != len(meta.TxsResults) {
		return fmt.Errorf("mismatched number of transaction results")
	}

	if err := s.filterAndDeliverEvents(ctx, svc, filter, height, nil, meta.BeginBlockEvents); err != nil {
		return err
	}

	for i, tx := range txs {
		if err := s.filterAndDeliverEvents(ctx, svc, filter, height, tx, meta.TxsResults[i].Events); err != nil {
			return err
		}
	}

	return s.filterAndDeliverEvents(ctx, svc, filter, height, nil, meta.EndBlockEvents)
}

func (s *Services) filterAndDeliverEvents(ctx context.Context, svc api.ServiceClient, filter *full.EventFilter, height int64, tx cmttypes.Tx, events []cmtabcitypes.Event) error {
	for _, ev := range filter.Apply(events) {
		if err := svc.DeliverEvent(ctx, height, tx, &ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *Services) updateEventFilter(svc api.ServiceClient, filter *full.EventFilter) {
	queryCh := svc.ServiceDescriptor().Queries()
	for {
		select {
		case query := <-queryCh:
			filter.Add(query)
		default:
			return
		}
	}
}
