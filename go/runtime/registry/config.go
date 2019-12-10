package registry

import (
	"fmt"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/runtime/history"
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

	// CfgHistoryTagIndexerBackend configures the history tag indexer backend.
	CfgHistoryTagIndexerBackend = "runtime.history.tag_indexer.backend"

	PrunerStrategyNone     = "none"
	PrunerStrategyKeepLast = "keep_last"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// RuntimeConfig is a per-runtime config.
type RuntimeConfig struct {
	// History configures the runtime history keeper.
	History history.Config
}

func newConfig() (*RuntimeConfig, error) {
	var cfg RuntimeConfig

	strategy := viper.GetString(CfgHistoryPrunerStrategy)
	switch strings.ToLower(strategy) {
	case PrunerStrategyNone:
		cfg.History.Pruner = history.NewNonePruner()
	case PrunerStrategyKeepLast:
		numKept := viper.GetUint64(CfgHistoryPrunerKeepLastNum)
		cfg.History.Pruner = history.NewKeepLastPruner(numKept)
	default:
		return nil, fmt.Errorf("runtime/registry: unknown history pruner strategy: %s", strategy)
	}

	cfg.History.PruneInterval = viper.GetDuration(CfgHistoryPrunerInterval)

	return &cfg, nil
}

func init() {
	Flags.StringSlice(CfgSupported, nil, "Add supported runtime ID (hex-encoded)")

	Flags.String(CfgHistoryPrunerStrategy, PrunerStrategyNone, "History pruner strategy")
	Flags.Duration(CfgHistoryPrunerInterval, 2*time.Minute, "History pruning interval")
	Flags.Uint64(CfgHistoryPrunerKeepLastNum, 600, "Keep last history pruner: number of last rounds to keep")

	_ = viper.BindPFlags(Flags)
}
