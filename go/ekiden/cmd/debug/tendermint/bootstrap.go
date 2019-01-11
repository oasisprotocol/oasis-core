package tendermint

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/tendermint/bootstrap"
)

const (
	cfgBootstrapAddress    = "debug.tendermint.bootstrap.address"
	cfgBootstrapValidators = "debug.tendermint.bootstrap.validators"
)

var (
	bootstrapCmd = &cobra.Command{
		Use:   "bootstrap",
		Short: "testnet bootstrap provisioning server",
		Run:   doBootstrap,
	}

	flagBootstrapAddress    string
	flagBootstrapValidators int
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

	if flagBootstrapValidators < 1 {
		logger.Error("insufficient validators",
			"validators", flagBootstrapValidators,
		)
		os.Exit(1)
	}

	svcMgr := background.NewServiceManager(logger)

	srv, err := bootstrap.NewServer(flagBootstrapAddress, flagBootstrapValidators, dataDir)
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

func registerBootstrap(parentCmd *cobra.Command) {
	bootstrapCmd.Flags().StringVar(&flagBootstrapAddress, cfgBootstrapAddress, ":19156", "server listen address")
	bootstrapCmd.Flags().IntVar(&flagBootstrapValidators, cfgBootstrapValidators, 3, "number of validators")

	for _, v := range []string{
		cfgBootstrapAddress,
		cfgBootstrapValidators,
	} {
		_ = viper.BindPFlag(v, bootstrapCmd.Flags().Lookup(v))
	}

	parentCmd.AddCommand(bootstrapCmd)
}
