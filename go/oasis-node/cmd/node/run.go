package node

import (
	"context"
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
)

type runnableNode interface {
	service.CleanupAble
	Wait()
}

// Run runs the Oasis node.
func Run(_ *cobra.Command, _ []string) {
	cmdCommon.SetIsNodeCmd(true)

	var (
		node runnableNode
		err  error
	)

	cfg := &config.GlobalConfig

	switch cfg.Mode {
	case config.ModeSeed:
		node, err = NewSeedNode(cfg)
	default:
		node, err = NewNode(cfg)
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
