package abci

import (
	"fmt"
	"strings"

	"github.com/tendermint/iavl"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
)

const (
	// PruneDefault is the default PruneStrategy.
	PruneDefault = pruneNone

	pruneNone  = "none"
	pruneKeepN = "keep_n"
)

// PruneStrategy is the strategy to use when pruning the ABCI mux iAVL
// state.
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
		return pruneNone
	case PruneKeepN:
		return pruneKeepN
	default:
		return "[unknown]"
	}
}

func (s *PruneStrategy) FromString(str string) error {
	switch strings.ToLower(str) {
	case pruneNone:
		*s = PruneNone
	case pruneKeepN:
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
	NumKept int64
}

// StatePruner is a concrete ABCI mux iAVL state pruner implementation.
type StatePruner interface {
	// Prune purges unneeded versions from the ABCI mux iAVL tree,
	// given the latest version, based on the underlying strategy.
	Prune(latestVersion int64)

	// Subscribe subscribes to prune events.
	Subscribe() (<-chan int64, *pubsub.Subscription, error)
}

type statePrunerInitializer interface {
	Initialize(latestVersion int64) error
}

type nonePruner struct{}

func (p *nonePruner) Prune(latestVersion int64) {
	// Nothing to prune.
}

func (p *nonePruner) Subscribe() (<-chan int64, *pubsub.Subscription, error) {
	return nil, nil, nil
}

type genericPruner struct {
	logger *logging.Logger
	tree   *iavl.MutableTree

	eldestRetained int64
	keepN          int64

	notifier *pubsub.Broker
}

func (p *genericPruner) Initialize(latestVersion int64) error {
	// Figure out the eldest version currently present in the tree.
	if p.eldestRetained = p.tree.EldestVersion(); p.eldestRetained == -1 {
		// The tree is empty, nothing to purge.
		p.eldestRetained = 0
		return nil
	}

	return p.doPrune(latestVersion)
}

func (p *genericPruner) Prune(latestVersion int64) {
	if err := p.doPrune(latestVersion); err != nil {
		p.logger.Error("Prune",
			"err", err,
		)
		panic(err)
	}
}

func (p *genericPruner) doPrune(latestVersion int64) error {
	if latestVersion < p.keepN {
		return nil
	}

	p.logger.Debug("Prune: Start",
		"latest_version", latestVersion,
		"start_version", p.eldestRetained,
	)

	preserveFrom := latestVersion - p.keepN
	for i := p.eldestRetained; i <= latestVersion; i++ {
		if p.tree.VersionExists(i) {
			if i >= preserveFrom {
				p.eldestRetained = i
				break
			}

			p.logger.Debug("Prune: Delete",
				"latest_version", latestVersion,
				"pruned_version", i,
			)

			if err := p.tree.DeleteVersion(i); err != nil {
				return err
			}

			p.notifier.Broadcast(i)
		}
	}

	p.logger.Debug("Prune: Finish",
		"latest_version", latestVersion,
		"eldest_version", p.eldestRetained,
	)

	return nil
}

func (p *genericPruner) Subscribe() (<-chan int64, *pubsub.Subscription, error) {
	sub := p.notifier.Subscribe()
	ch := make(chan int64)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func newStatePruner(cfg *PruneConfig, tree *iavl.MutableTree, latestVersion int64) (StatePruner, error) {
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
			logger:   logger,
			tree:     tree,
			keepN:    cfg.NumKept,
			notifier: pubsub.NewBroker(false),
		}
	default:
		return nil, fmt.Errorf("abci/pruner: unsupported pruning strategy: %v", cfg.Strategy)
	}

	if initializer, ok := statePruner.(statePrunerInitializer); ok {
		if err := initializer.Initialize(latestVersion); err != nil {
			return nil, err
		}
	}

	logger.Debug("ABCI state pruner initialized",
		"strategy", cfg.Strategy,
		"num_kept", cfg.NumKept,
	)

	return statePruner, nil
}
