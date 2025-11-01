package abci

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/config"
	nodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

const (
	// LogEventABCIPruneDelete is a log event value that signals an ABCI pruning
	// delete event.
	LogEventABCIPruneDelete = "cometbft/abci/prune"
)

// PruneStrategy is the strategy to use when pruning the ABCI mux state.
type PruneStrategy int

const (
	// PruneNone retains all versions.
	PruneNone PruneStrategy = iota

	// PruneKeepN retains the last N latest versions.
	PruneKeepN
)

func (s PruneStrategy) String() string {
	switch s {
	case PruneNone:
		return config.PruneStrategyNone
	case PruneKeepN:
		return config.PruneStrategyKeepN
	default:
		return "[unknown]"
	}
}

func (s *PruneStrategy) FromString(str string) error {
	switch strings.ToLower(str) {
	case config.PruneStrategyNone:
		*s = PruneNone
	case config.PruneStrategyKeepN:
		*s = PruneKeepN
	default:
		return fmt.Errorf("abci/pruner: unknown pruning strategy: '%v'", str)
	}

	return nil
}

// PruneConfig is the pruning strategy and related configuration.
type PruneConfig struct {
	// Strategy is the PruneStrategy used.
	Strategy PruneStrategy

	// NumKept is the number of versions retained when applicable.
	NumKept uint64

	// PruneInterval configures the pruning interval.
	PruneInterval time.Duration
}

// StatePruner is a concrete ABCI mux state pruner implementation.
type StatePruner interface {
	consensus.StatePruner

	// Prune purges unneeded versions from the ABCI mux node database,
	// given the latest version, based on the underlying strategy.
	//
	// This method is NOT safe for concurrent use.
	Prune(latestVersion uint64) error

	// GetLastRetainedVersion returns the earliest version below which all
	// versions can be discarded from block history. Zero indicates that
	// no versions can be discarded.
	//
	// This method can be called concurrently with Prune.
	GetLastRetainedVersion() uint64
}

type nonePruner struct{}

func (p *nonePruner) Prune(uint64) error {
	// Nothing to prune.
	return nil
}

func (p *nonePruner) RegisterHandler(consensus.StatePruneHandler) {
}

func (p *nonePruner) GetLastRetainedVersion() uint64 {
	return 0
}

type genericPruner struct {
	sync.Mutex

	logger *logging.Logger
	ndb    nodedb.NodeDB

	earliestVersion     uint64
	keepN               uint64
	lastRetainedVersion uint64

	handlers []consensus.StatePruneHandler
}

func (p *genericPruner) GetLastRetainedVersion() uint64 {
	p.Lock()
	defer p.Unlock()
	return p.lastRetainedVersion
}

func (p *genericPruner) Prune(latestVersion uint64) error {
	if latestVersion < p.keepN {
		return nil
	}
	if p.earliestVersion == 0 {
		// Figure out the eldest version currently present in the tree.
		p.earliestVersion = p.ndb.GetEarliestVersion()
		// Initially, the earliest version is the last retained version.
		p.lastRetainedVersion = p.earliestVersion
	}
	if p.earliestVersion == 0 {
		return nil
	}

	p.logger.Debug("Prune: Start",
		"latest_version", latestVersion,
		"start_version", p.earliestVersion,
	)

	preserveFrom := latestVersion - p.keepN
	for i := p.earliestVersion; i <= latestVersion; i++ {
		if i >= preserveFrom {
			p.earliestVersion = i
			break
		}

		if err := p.canPrune(int64(i)); err != nil {
			p.logger.Debug("prune handler blocked pruning version",
				"err", err,
				"latest_version", latestVersion,
				"version", i,
			)
			p.earliestVersion = i
			break
		}

		p.logger.Debug("Prune: Delete",
			"latest_version", latestVersion,
			"pruned_version", i,
			logging.LogEvent, LogEventABCIPruneDelete,
		)

		err := p.ndb.Prune(i)
		switch err {
		case nil:
		case nodedb.ErrNotEarliest:
			p.logger.Debug("Prune: skipping non-earliest version",
				"version", i,
			)
			continue
		default:
			return err
		}
	}

	// Make sure to sync the underlying database before updating what can be discarded. Otherwise
	// things can be pruned and in case of a crash replay will not be possible.
	if err := p.ndb.Sync(); err != nil {
		return fmt.Errorf("failed to sync state database: %w", err)
	}

	// We can discard everything below the earliest version.
	p.Lock()
	p.lastRetainedVersion = p.earliestVersion
	p.Unlock()

	p.logger.Debug("Prune: Finish",
		"latest_version", latestVersion,
		"eldest_version", p.earliestVersion,
	)

	return nil
}

// canPrune checks if any of the prune handlers does not allow pruning of the given version.
func (p *genericPruner) canPrune(v int64) error {
	for _, ph := range p.handlers {
		if err := ph.CanPruneConsensus(v); err != nil {
			return err
		}
	}
	return nil
}

func (p *genericPruner) RegisterHandler(handler consensus.StatePruneHandler) {
	p.Lock()
	defer p.Unlock()

	p.handlers = append(p.handlers, handler)
}

func newStatePruner(cfg *PruneConfig, ndb nodedb.NodeDB) (StatePruner, error) {
	// The roothash checkCommittees call requires at least 1 previous block
	// for timekeeping purposes.
	const minKept = 1

	logger := logging.GetLogger("abci-mux/pruner")

	var statePruner StatePruner
	switch cfg.Strategy {
	case PruneNone:
		statePruner = &nonePruner{}
	case PruneKeepN:
		if cfg.NumKept < minKept {
			return nil, fmt.Errorf("abci/pruner: invalid number of versions retained: %v", cfg.NumKept)
		}

		statePruner = &genericPruner{
			logger: logger,
			ndb:    ndb,
			keepN:  cfg.NumKept,
		}
	default:
		return nil, fmt.Errorf("abci/pruner: unsupported pruning strategy: %v", cfg.Strategy)
	}

	logger.Debug("ABCI state pruner created",
		"strategy", cfg.Strategy,
		"num_kept", cfg.NumKept,
	)

	return statePruner, nil
}
