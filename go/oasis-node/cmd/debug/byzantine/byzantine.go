package byzantine

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

const (
	// CfgFakeSGX configures registering with SGX capability.
	CfgFakeSGX = "fake_sgx"
	// CfgVersionFakeEnclaveID configures runtime's EnclaveIdentity.
	CfgVersionFakeEnclaveID = "runtime.version.fake_enclave_id"
	// CfgActivationEpoch configures the epoch at which the Byzantine node activates.
	CfgActivationEpoch = "activation_epoch"
)

var (
	logger       = logging.GetLogger("cmd/byzantine")
	byzantineCmd = &cobra.Command{
		Use:              "byzantine",
		Short:            "run some node behaviors for testing, often not honest",
		PersistentPreRun: activateCommonConfig,
	}
	executorHonestCmd = &cobra.Command{
		Use:   "executor-honest",
		Short: "act as an honest executor worker",
		Run:   doExecutorHonest,
	}
	executorWrongCmd = &cobra.Command{
		Use:   "executor-wrong",
		Short: "act as an executor worker that sends wrong output",
		Run:   doExecutorWrong,
	}
	executorStragglerCmd = &cobra.Command{
		Use:   "executor-straggler",
		Short: "act as an executor worker that registers and doesn't do any work",
		Run:   doExecutorStraggler,
	}
)

func activateCommonConfig(cmd *cobra.Command, args []string) {
	// This subcommand is used in networks where other nodes are honest or colluding with us.
	// Set this so we don't reject things when we run without real IAS.
	ias.SetSkipVerify()
	ias.SetAllowDebugEnclaves()
}

func doExecutorHonest(cmd *cobra.Command, args []string) {
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
	if err = ph.start(ht, defaultIdentity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("P2P start failed: %+v", err))
	}
	defer func() {
		if err1 := ph.stop(); err1 != nil {
			panic(fmt.Sprintf("P2P stop failed: %+v", err1))
		}
	}()

	activationEpoch := epochtime.EpochTime(viper.GetUint64(CfgActivationEpoch))
	if err = epochtimeWaitForEpoch(ht.service, activationEpoch); err != nil {
		panic(fmt.Sprintf("epochtimeWaitForEpoch: %+v", err))
	}

	var capabilities *node.Capabilities
	var rak signature.Signer
	if viper.GetBool(CfgFakeSGX) {
		if rak, capabilities, err = initFakeCapabilitiesSGX(); err != nil {
			panic(fmt.Sprintf("initFakeCapabilitiesSGX: %+v", err))
		}
	}
	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Addresses(), defaultRuntimeID, capabilities, node.RoleComputeWorker); err != nil {
		panic(fmt.Sprintf("registryRegisterNode: %+v", err))
	}

	electionHeight, err := schedulerNextElectionHeight(ht.service, activationEpoch+1)
	if err != nil {
		panic(fmt.Sprintf("scheduler next election height failed: %+v", err))
	}
	executorCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindComputeExecutor, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s at height %d failed: %+v", scheduler.KindComputeExecutor, electionHeight, err))
	}
	if err = schedulerCheckScheduled(executorCommittee, defaultIdentity.NodeSigner.Public(), scheduler.Worker); err != nil {
		panic(fmt.Sprintf("scheduler check scheduled failed: %+v", err))
	}
	logger.Debug("executor honest: executor schedule ok")
	storageCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindStorage, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindStorage, err))
	}
	transactionSchedulerCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindComputeTxnScheduler, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindComputeTxnScheduler, err))
	}
	if err = schedulerCheckNotScheduled(transactionSchedulerCommittee, defaultIdentity.NodeSigner.Public()); err != nil {
		panic(fmt.Sprintf("scheduler check not scheduled txnscheduler failed: %+v", err))
	}

	logger.Debug("executor honest: connecting to storage committee")
	hnss, err := storageConnectToCommittee(ht, electionHeight, storageCommittee, scheduler.Worker, defaultIdentity)
	if err != nil {
		panic(fmt.Sprintf("storage connect to committee failed: %+v", err))
	}
	defer storageBroadcastCleanup(hnss)

	cbc := newComputeBatchContext()

	if err = cbc.receiveBatch(ph); err != nil {
		panic(fmt.Sprintf("compute receive batch failed: %+v", err))
	}
	logger.Debug("executor honest: received batch", "bd", cbc.bd)

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

	if err = cbc.commitTrees(ctx); err != nil {
		panic(fmt.Sprintf("compute commit trees failed: %+v", err))
	}
	logger.Debug("executor honest: committed storage trees",
		"io_write_log", cbc.ioWriteLog,
		"new_io_root", cbc.newIORoot,
		"state_write_log", cbc.stateWriteLog,
		"new_state_root", cbc.newStateRoot,
	)

	if err = cbc.uploadBatch(ctx, hnss); err != nil {
		panic(fmt.Sprintf("compute upload batch failed: %+v", err))
	}

	if err = cbc.createCommitment(defaultIdentity, rak, executorCommittee.EncodedMembersHash()); err != nil {
		panic(fmt.Sprintf("compute create commitment failed: %+v", err))
	}

	if err = cbc.publishToChain(ht.service, defaultIdentity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
	}
	logger.Debug("executor honest: commitment sent")
}

func doExecutorWrong(cmd *cobra.Command, args []string) {
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
	if err = ph.start(ht, defaultIdentity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("P2P start failed: %+v", err))
	}
	defer func() {
		if err1 := ph.stop(); err1 != nil {
			panic(fmt.Sprintf("P2P stop failed: %+v", err1))
		}
	}()

	activationEpoch := epochtime.EpochTime(viper.GetUint64(CfgActivationEpoch))
	if err = epochtimeWaitForEpoch(ht.service, activationEpoch); err != nil {
		panic(fmt.Sprintf("epochtimeWaitForEpoch: %+v", err))
	}

	var capabilities *node.Capabilities
	var rak signature.Signer
	if viper.GetBool(CfgFakeSGX) {
		if rak, capabilities, err = initFakeCapabilitiesSGX(); err != nil {
			panic(fmt.Sprintf("initFakeCapabilitiesSGX: %+v", err))
		}
	}
	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Addresses(), defaultRuntimeID, capabilities, node.RoleComputeWorker); err != nil {
		panic(fmt.Sprintf("registryRegisterNode: %+v", err))
	}

	electionHeight, err := schedulerNextElectionHeight(ht.service, activationEpoch+1)
	if err != nil {
		panic(fmt.Sprintf("scheduler next election height failed: %+v", err))
	}
	executorCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindComputeExecutor, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s at height %d failed: %+v", scheduler.KindComputeExecutor, electionHeight, err))
	}
	if err = schedulerCheckScheduled(executorCommittee, defaultIdentity.NodeSigner.Public(), scheduler.Worker); err != nil {
		panic(fmt.Sprintf("scheduler check scheduled failed: %+v", err))
	}
	logger.Debug("executor wrong: executor schedule ok")
	storageCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindStorage, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindStorage, err))
	}
	transactionSchedulerCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindComputeTxnScheduler, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindComputeTxnScheduler, err))
	}
	if err = schedulerCheckNotScheduled(transactionSchedulerCommittee, defaultIdentity.NodeSigner.Public()); err != nil {
		panic(fmt.Sprintf("scheduler check not scheduled txnscheduler failed: %+v", err))
	}

	logger.Debug("executor honest: connecting to storage committee")
	hnss, err := storageConnectToCommittee(ht, electionHeight, storageCommittee, scheduler.Worker, defaultIdentity)
	if err != nil {
		panic(fmt.Sprintf("storage connect to committee failed: %+v", err))
	}
	defer storageBroadcastCleanup(hnss)

	cbc := newComputeBatchContext()

	if err = cbc.receiveBatch(ph); err != nil {
		panic(fmt.Sprintf("compute receive batch failed: %+v", err))
	}
	logger.Debug("executor wrong: received batch", "bd", cbc.bd)

	ctx := context.Background()

	if err = cbc.openTrees(ctx, hnss[0]); err != nil {
		panic(fmt.Sprintf("compute open trees failed: %+v", err))
	}
	defer cbc.closeTrees()

	// Alter the state wrong.
	if err = cbc.stateTree.Insert(ctx, []byte("hello_key"), []byte("wrong")); err != nil {
		panic(fmt.Sprintf("compute state tree set failed: %+v", err))
	}
	if err = cbc.addResultSuccess(ctx, cbc.txs[0], nil, transaction.Tags{
		transaction.Tag{Key: []byte("kv_op"), Value: []byte("insert")},
		transaction.Tag{Key: []byte("kv_key"), Value: []byte("hello_key")},
	}); err != nil {
		panic(fmt.Sprintf("compute add result success failed: %+v", err))
	}

	if err = cbc.commitTrees(ctx); err != nil {
		panic(fmt.Sprintf("compute commit trees failed: %+v", err))
	}
	logger.Debug("executor wrong: committed storage trees",
		"io_write_log", cbc.ioWriteLog,
		"new_io_root", cbc.newIORoot,
		"state_write_log", cbc.stateWriteLog,
		"new_state_root", cbc.newStateRoot,
	)

	if err = cbc.uploadBatch(ctx, hnss); err != nil {
		panic(fmt.Sprintf("compute upload batch failed: %+v", err))
	}

	if err = cbc.createCommitment(defaultIdentity, rak, executorCommittee.EncodedMembersHash()); err != nil {
		panic(fmt.Sprintf("compute create commitment failed: %+v", err))
	}

	if err = cbc.publishToChain(ht.service, defaultIdentity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
	}
	logger.Debug("executor wrong: commitment sent")
}

func doExecutorStraggler(cmd *cobra.Command, args []string) {
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
	if err = ph.start(ht, defaultIdentity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("P2P start failed: %+v", err))
	}
	defer func() {
		if err1 := ph.stop(); err1 != nil {
			panic(fmt.Sprintf("P2P stop failed: %+v", err1))
		}
	}()

	activationEpoch := epochtime.EpochTime(viper.GetUint64(CfgActivationEpoch))
	if err = epochtimeWaitForEpoch(ht.service, activationEpoch); err != nil {
		panic(fmt.Sprintf("epochtimeWaitForEpoch: %+v", err))
	}

	var capabilities *node.Capabilities
	if viper.GetBool(CfgFakeSGX) {
		if _, capabilities, err = initFakeCapabilitiesSGX(); err != nil {
			panic(fmt.Sprintf("initFakeCapabilitiesSGX: %+v", err))
		}
	}
	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Addresses(), defaultRuntimeID, capabilities, node.RoleComputeWorker); err != nil {
		panic(fmt.Sprintf("registryRegisterNode: %+v", err))
	}

	electionHeight, err := schedulerNextElectionHeight(ht.service, activationEpoch+1)
	if err != nil {
		panic(fmt.Sprintf("scheduler next election height failed: %+v", err))
	}
	executorCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindComputeExecutor, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s at height %d failed: %+v", scheduler.KindComputeExecutor, electionHeight, err))
	}
	if err = schedulerCheckScheduled(executorCommittee, defaultIdentity.NodeSigner.Public(), scheduler.Worker); err != nil {
		panic(fmt.Sprintf("scheduler check scheduled failed: %+v", err))
	}
	logger.Debug("executor straggler: executor schedule ok")
	transactionSchedulerCommittee, err := schedulerGetCommittee(ht, electionHeight, scheduler.KindComputeTxnScheduler, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindComputeTxnScheduler, err))
	}
	if err = schedulerCheckNotScheduled(transactionSchedulerCommittee, defaultIdentity.NodeSigner.Public()); err != nil {
		panic(fmt.Sprintf("scheduler check not scheduled txnscheduler failed: %+v", err))
	}

	cbc := newComputeBatchContext()

	if err = cbc.receiveBatch(ph); err != nil {
		panic(fmt.Sprintf("compute receive batch failed: %+v", err))
	}
	logger.Debug("executor straggler: received batch", "bd", cbc.bd)

	logger.Debug("executor straggler: bailing")
}

// Register registers the byzantine sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	byzantineCmd.AddCommand(executorHonestCmd)
	byzantineCmd.AddCommand(executorWrongCmd)
	byzantineCmd.AddCommand(executorStragglerCmd)
	parentCmd.AddCommand(byzantineCmd)
}

func init() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.Bool(CfgFakeSGX, false, "register with SGX capability")
	fs.String(CfgVersionFakeEnclaveID, "", "fake runtime enclave identity")
	fs.Uint64(CfgActivationEpoch, 0, "epoch at which the Byzantine node should activate")
	_ = viper.BindPFlags(fs)
	byzantineCmd.PersistentFlags().AddFlagSet(fs)

	byzantineCmd.PersistentFlags().AddFlagSet(metrics.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.DebugDontBlameOasisFlag)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.DebugTestEntityFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(grpc.ServerLocalFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(p2p.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(tendermint.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(registration.Flags)
}
