package registry

import (
	"fmt"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/runtime/history"
	"github.com/oasislabs/oasis-core/go/runtime/tagindexer"
)

const (
	// CfgSupported configures a supported runtime ID.
	CfgSupported = "runtime.supported"

	// CfgHistoryPrunerStrategy configures the history pruner strategy.
	CfgHistoryPrunerStrategy = "runtime.history.pruner.strategy"
	// CfgHistoryPrunerInterval configures the history pruner interval.
	CfgHistoryPrunerInterval = "runtime.history.pruner.interval"
	// CfgHistoryPrunerKeepLastNum configures the number of last kept
	// rounds when using the "keep last" pruner strategy.
	CfgHistoryPrunerKeepLastNum = "runtime.history.pruner.num_kept"

	// CfgTagIndexerBackend configures the history tag indexer backend.
	CfgTagIndexerBackend = "runtime.history.tag_indexer.backend"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// RuntimeConfig is a per-runtime config.
type RuntimeConfig struct {
	// History configures the runtime history keeper.
	History history.Config

	// TagIndexer configures the tag indexer backend.
	TagIndexer tagindexer.BackendFactory
}

func newConfig() (*RuntimeConfig, error) {
	var cfg RuntimeConfig

	strategy := viper.GetString(CfgHistoryPrunerStrategy)
	switch strings.ToLower(strategy) {
	case history.PrunerStrategyNone:
		cfg.History.Pruner = history.NewNonePruner()
	case history.PrunerStrategyKeepLast:
		numKept := viper.GetUint64(CfgHistoryPrunerKeepLastNum)
		cfg.History.Pruner = history.NewKeepLastPruner(numKept)
	default:
		return nil, fmt.Errorf("runtime/registry: unknown history pruner strategy: %s", strategy)
	}

	cfg.History.PruneInterval = viper.GetDuration(CfgHistoryPrunerInterval)

	tagIndexer := viper.GetString(CfgTagIndexerBackend)
	switch strings.ToLower(tagIndexer) {
	case "":
		cfg.TagIndexer = tagindexer.NewNopBackend()
	case tagindexer.BleveBackendName:
		cfg.TagIndexer = tagindexer.NewBleveBackend()
	default:
		return nil, fmt.Errorf("runtime/registry: unknown tag indexer backend: %s", tagIndexer)
	}

	return &cfg, nil
}

func init() {
	Flags.StringSlice(CfgSupported, nil, "Add supported runtime ID (hex-encoded)")

	Flags.String(CfgHistoryPrunerStrategy, history.PrunerStrategyNone, "History pruner strategy")
	Flags.Duration(CfgHistoryPrunerInterval, 2*time.Minute, "History pruning interval")
	Flags.Uint64(CfgHistoryPrunerKeepLastNum, 600, "Keep last history pruner: number of last rounds to keep")

	Flags.String(CfgTagIndexerBackend, "", "Runtime tag indexer backend (disabled by default)")

	_ = viper.BindPFlags(Flags)
}
