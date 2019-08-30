package byzantine

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/tendermint"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
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

	defaultIdentity, err := initDefaultIdentity(common.DataDir())
	if err != nil {
		panic(fmt.Sprintf("init default identity failed: %+v", err))
	}

	ht := newHonestTendermint()
	if err = ht.start(defaultIdentity, common.DataDir()); err != nil {
		panic(fmt.Sprintf("honest Tendermint start failed: %+v", err))
	}
	defer func() {
		if err1 := ht.stop(); err1 != nil {
			panic(fmt.Sprintf("honest Tendermint stop failed: %+v", err1))
		}
	}()

	ph := newP2PHandle()
	if err = ph.start(defaultIdentity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("P2P start failed: %+v", err))
	}
	defer func() {
		if err1 := ph.stop(); err1 != nil {
			panic(fmt.Sprintf("P2P stop failed: %+v", err1))
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
	computeHonestCmd.Flags().AddFlagSet(p2p.Flags)
	computeHonestCmd.Flags().AddFlagSet(tendermint.Flags)
}
