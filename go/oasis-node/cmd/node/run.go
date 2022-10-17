package node

import (
	"context"
	"errors"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/service"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
)

const (
	// ModeValidator is the name of the validator node mode.
	ModeValidator string = "validator"

	// ModeNonValidator is the name of the non-validator node mode.
	ModeNonValidator string = "non-validator"

	// ModeCompute is the name of the compute node mode.
	ModeCompute string = "compute"

	// ModeKeyManager is the name of the key manager node mode.
	ModeKeyManager string = "keymanager"

	// ModeClient is the name of the client node mode.
	ModeClient string = "client"

	// ModeStatelessClient is the name of the stateless client node mode.
	ModeStatelessClient string = "client-stateless"

	// ModeSeed is the name of the seed node mode.
	ModeSeed string = "seed"

	// ModeArchive is the name of the archive node mode.
	ModeArchive string = "archive"
)

func Mode() string {
	return viper.GetString(CfgMode)
}

type runnableNode interface {
	service.CleanupAble
	Wait()
}

// Run runs the Oasis node.
func Run(cmd *cobra.Command, args []string) {
	cmdCommon.SetIsNodeCmd(true)

	var (
		node runnableNode
		err  error
	)

	switch Mode() {
	case ModeSeed:
		node, err = NewSeedNode()
	default:
		node, err = NewNode()
	}

	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		// Shutdown requested during startup.
		return
	default:
		os.Exit(1)
	}

	defer node.Cleanup()
	node.Wait()
}
