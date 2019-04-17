package tendermint

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	"github.com/oasislabs/ekiden/go/tendermint/bootstrap"
)

const (
	cfgBootstrapAddress    = "debug.tendermint.bootstrap.address"
	cfgBootstrapValidators = "debug.tendermint.bootstrap.validators"
	cfgBootstrapSeeds      = "debug.tendermint.bootstrap.seeds"
	cfgBootstrapRuntime    = "debug.tendermint.bootstrap.runtime"
	cfgBootstrapEntity     = "debug.tendermint.bootstrap.entity"
	cfgBootstrapRootHash   = "debug.tendermint.bootstrap.roothash"
)

var (
	bootstrapCmd = &cobra.Command{
		Use:   "bootstrap",
		Short: "testnet bootstrap provisioning server",
		PreRun: func(cmd *cobra.Command, args []string) {
			registerBootstrapFlags(cmd)
		},
		Run: doBootstrap,
	}
)

func doBootstrap(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	logger := logging.GetLogger("cmd/debug/tendermint/bootstrap")
	logger.Warn("The bootstrap provisioning server is NOT FOR PRODUCTION USE.")

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Warn("data directory not set, genesis file will not be persisted")
	}

	bootstrapValidators := viper.GetInt(cfgBootstrapValidators)
	if bootstrapValidators < 1 {
		logger.Error("insufficient validators",
			"validators", bootstrapValidators,
		)
		os.Exit(1)
	}

	st := &api.GenesisAppState{
		ABCIAppState: make(map[string][]byte),
	}
	entities := viper.GetStringSlice(cfgBootstrapEntity)
	runtimes := viper.GetStringSlice(cfgBootstrapRuntime)
	if err := tendermint.AppendRegistryState(st, entities, runtimes, logger); err != nil {
		logger.Error("failed to parse registry genesis state",
			"err", err,
		)
		os.Exit(1)
	}

	roothash := viper.GetStringSlice(cfgBootstrapRootHash)
	if err := tendermint.AppendRootHashState(st, roothash, logger); err != nil {
		logger.Error("failed to parse roothash genesis state",
			"err", err,
		)
		os.Exit(1)
	}

	if len(st.ABCIAppState) == 0 {
		st = nil
	}

	bootstrapSeeds := viper.GetInt(cfgBootstrapSeeds)

	svcMgr := background.NewServiceManager(logger)

	bootstrapAddr := viper.GetString(cfgBootstrapAddress)
	srv, err := bootstrap.NewServer(bootstrapAddr, bootstrapValidators, bootstrapSeeds, st, dataDir)
	if err != nil {
		logger.Error("failed to initialize bootstrap server",
			"err", err,
		)
		os.Exit(1)
	}
	svcMgr.Register(srv)

	if err = srv.Start(); err != nil {
		logger.Error("failed to start bootstrap server",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("initialization complete: will bootstrap")

	svcMgr.Wait()
}

func registerBootstrapFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBootstrapAddress, ":19156", "server listen address")
		cmd.Flags().Int(cfgBootstrapValidators, 3, "number of validators")
		cmd.Flags().Int(cfgBootstrapSeeds, 1, "number of seeds")
		cmd.Flags().StringSlice(cfgBootstrapEntity, nil, "path to entity registration file")
		cmd.Flags().StringSlice(cfgBootstrapRuntime, nil, "path to runtime registration file")
		cmd.Flags().StringSlice(cfgBootstrapRootHash, nil, "path to roothash genesis blocks file")
	}

	for _, v := range []string{
		cfgBootstrapAddress,
		cfgBootstrapValidators,
		cfgBootstrapSeeds,
		cfgBootstrapRuntime,
		cfgBootstrapEntity,
		cfgBootstrapRootHash,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerBootstrap(parentCmd *cobra.Command) {
	registerBootstrapFlags(bootstrapCmd)

	parentCmd.AddCommand(bootstrapCmd)
}
