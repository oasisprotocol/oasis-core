package registry

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
)

func getLocalConfig(runtimeID common.Namespace) map[string]interface{} {
	return config.GlobalConfig.Runtime.GetLocalConfig(runtimeID)
}

func getConfiguredRuntimeIDs() ([]common.Namespace, error) {
	// Check if any runtimes are configured to be hosted.
	runtimes := make(map[common.Namespace]struct{})
	for _, cfg := range config.GlobalConfig.Runtime.Runtimes {
		runtimes[cfg.ID] = struct{}{}
	}

	// Support legacy configurations where runtimes are specified within
	// configured bundles.
	for _, path := range config.GlobalConfig.Runtime.Paths {
		if err := func() error {
			bnd, err := bundle.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open bundle: %w", err)
			}
			defer bnd.Close()

			runtimes[bnd.Manifest.ID] = struct{}{}
			return nil
		}(); err != nil {
			return nil, err
		}
	}

	if cmdFlags.DebugDontBlameOasis() && viper.IsSet(bundle.CfgDebugMockIDs) {
		// Allow the mock provisioner to function, as it does not use an actual
		// runtime. This is only used for the basic node tests.
		for _, str := range viper.GetStringSlice(bundle.CfgDebugMockIDs) {
			var runtimeID common.Namespace
			if err := runtimeID.UnmarshalText([]byte(str)); err != nil {
				return nil, fmt.Errorf("failed to deserialize runtime ID: %w", err)
			}
			runtimes[runtimeID] = struct{}{}
		}

		// Skip validation
		return slices.Collect(maps.Keys(runtimes)), nil
	}

	// Validate configured runtimes based on the runtime mode.
	switch config.GlobalConfig.Mode {
	case config.ModeValidator, config.ModeSeed:
		// No runtimes should be configured.
		if len(runtimes) > 0 && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("no runtimes should be configured when in validator or seed modes")
		}
	case config.ModeCompute, config.ModeKeyManager, config.ModeStatelessClient:
		// At least one runtime should be configured.
		if len(runtimes) == 0 && !cmdFlags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("at least one runtime must be configured when in compute, keymanager, or client-stateless modes")
		}
	default:
		// In any other mode, runtimes can be optionally configured.
	}

	return slices.Collect(maps.Keys(runtimes)), nil
}

func createHistoryFactory() (history.Factory, error) {
	var pruneFactory history.PrunerFactory
	strategy := config.GlobalConfig.Runtime.Prune.Strategy
	switch strings.ToLower(strategy) {
	case history.PrunerStrategyNone:
		pruneFactory = history.NewNonePrunerFactory()
	case history.PrunerStrategyKeepLast:
		numKept := config.GlobalConfig.Runtime.Prune.NumKept
		pruneInterval := max(config.GlobalConfig.Runtime.Prune.Interval, time.Second)
		pruneFactory = history.NewKeepLastPrunerFactory(numKept, pruneInterval)
	default:
		return nil, fmt.Errorf("runtime/registry: unknown history pruner strategy: %s", strategy)
	}

	// Archive node won't commit any new blocks, so disable waiting for storage
	// sync commits.
	mode := config.GlobalConfig.Mode
	hasLocalStorage := mode.HasLocalStorage() && !mode.IsArchive()

	historyFactory := history.NewFactory(pruneFactory, hasLocalStorage)

	return historyFactory, nil
}
