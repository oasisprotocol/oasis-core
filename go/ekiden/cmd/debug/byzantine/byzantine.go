package byzantine

import (
	"context"
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
	"github.com/oasislabs/ekiden/go/worker/registration"
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

	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), []node.Address{node.Address{
		TCPAddr: net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 11004,
		},
	}}, ph.service.Info(), defaultRuntimeID, node.RoleComputeWorker); err != nil {
		panic(fmt.Sprintf("registryRegisterNode: %+v", err))
	}

	electionHeight, err := schedulerNextElectionHeight(ht.service, scheduler.KindCompute)
	if err != nil {
		panic(fmt.Sprintf("scheduler next election height failed: %+v", err))
	}
	computeCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindCompute, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindCompute, err))
	}
	if err = schedulerCheckScheduled(computeCommittee, defaultIdentity.NodeSigner.Public(), scheduler.Worker); err != nil {
		panic(fmt.Sprintf("scheduler check scheduled failed: %+v", err))
	}
	logger.Debug("compute honest: compute schedule ok")
	storageCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindStorage, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindStorage, err))
	}
	mergeCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindMerge, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindMerge, err))
	}

	logger.Debug("compute honest: connecting to storage committee")
	hnss, err := storageConnectToCommittee(ht.service, electionHeight, storageCommittee, scheduler.Worker, defaultIdentity)
	if err != nil {
		panic(fmt.Sprintf("storage connect to committee failed: %+v", err))
	}
	defer storageBroadcastCleanup(hnss)

	cbc := newComputeBatchContext()

	if err = cbc.receiveBatch(ph); err != nil {
		panic(fmt.Sprintf("compute receive batch failed: %+v", err))
	}
	logger.Debug("compute honest: received batch", "bd", cbc.bd)

	ctx := context.Background()

	if err = cbc.openTrees(ctx, hnss[0]); err != nil {
		panic(fmt.Sprintf("compute open trees failed: %+v", err))
	}
	defer cbc.closeTrees()

	// Process transaction honestly.
	if err = cbc.stateTree.Insert(ctx, []byte("hello_key"), []byte("hello_value")); err != nil {
		panic(fmt.Sprintf("compute state tree set failed: %+v", err))
	}
	if err = cbc.addResultSuccess(ctx, cbc.txs[0], nil, transaction.Tags{
		transaction.Tag{Key: []byte("kv_op"), Value: []byte("insert")},
		transaction.Tag{Key: []byte("kv_key"), Value: []byte("hello_key")},
	}); err != nil {
		panic(fmt.Sprintf("compute add result success failed: %+v", err))
	}

	if err = cbc.commit(ctx); err != nil {
		panic(fmt.Sprintf("compute commit failed: %+v", err))
	}
	logger.Debug("compute honest: committed storage trees",
		"io_write_log", cbc.ioWriteLog,
		"new_io_root", cbc.newIORoot,
		"state_write_log", cbc.stateWriteLog,
		"new_state_root", cbc.newStateRoot,
	)

	receipts, err := cbc.uploadBatch(ctx, hnss)
	if err != nil {
		panic(fmt.Sprintf("compute upload batch failed: %+v", err))
	}

	message, err := cbc.createCommitmentMessage(defaultIdentity, defaultRuntimeID, electionHeight, computeCommittee.EncodedMembersHash(), receipts)
	if err != nil {
		panic(fmt.Sprintf("compute create commitment message failed: %+v", err))
	}

	if err = computePublishToCommittee(ht.service, electionHeight, mergeCommittee, scheduler.Worker, ph, message); err != nil {
		panic(fmt.Sprintf("compute publish to committee merge worker failed: %+v", err))
	}
	logger.Debug("compute honest: commitment sent")
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
	computeHonestCmd.Flags().AddFlagSet(registration.Flags)
}
