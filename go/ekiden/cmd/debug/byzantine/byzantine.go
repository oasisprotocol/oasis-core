package byzantine

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/tendermint"
)

var (
	logger       = logging.GetLogger("cmd/byzantine")
	byzantineCmd = &cobra.Command{
		Use:   "byzantine",
		Short: "run some node behaviors for testing, often not honest",
	}
	computeHonestCmd = &cobra.Command{
		Use:   "compute-honest",
		Short: "act as an honest compute worker",
		Run:   doComputeHonest,
	}
)

func doComputeHonest(cmd *cobra.Command, args []string) {
	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	ht := newHonestTendermint()
	if err := ht.start(common.DataDir()); err != nil {
		panic(fmt.Sprintf("honest Tendermint start failed: %+v", err))
	}
	defer func() {
		if err := ht.stop(); err != nil {
			panic(fmt.Sprintf("honest Tendermint stop failed: %+v", err))
		}
	}()

	logger.Warn("compute honest: mostly not implemented")
}

// Register registers the byzantine sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	byzantineCmd.AddCommand(computeHonestCmd)
	parentCmd.AddCommand(byzantineCmd)
}

func init() {
	computeHonestCmd.Flags().AddFlagSet(flags.GenesisFileFlags)
	computeHonestCmd.Flags().AddFlagSet(tendermint.Flags)
}
