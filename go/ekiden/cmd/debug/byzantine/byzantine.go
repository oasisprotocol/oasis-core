package byzantine

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgFakeSGX       = "fake_sgx"
	cfgMockEpochTime = "mock_epochtime"
)

var (
	logger       = logging.GetLogger("cmd/byzantine")
	byzantineCmd = &cobra.Command{
		Use:              "byzantine",
		Short:            "run some node behaviors for testing, often not honest",
		PersistentPreRun: activateCommonConfig,
	}
	computeHonestCmd = &cobra.Command{
		Use:   "compute-honest",
		Short: "act as an honest compute worker",
		Run:   doComputeHonest,
	}
	computeWrongCmd = &cobra.Command{
		Use:   "compute-wrong",
		Short: "act as a compute worker that sends wrong output",
		Run:   doComputeWrong,
	}
	computeStragglerCmd = &cobra.Command{
		Use:   "compute-straggler",
		Short: "act as a compute worker that registers and doesn't do any work",
		Run:   doComputeStraggler,
	}
	mergeHonestCmd = &cobra.Command{
		Use:   "merge-honest",
		Short: "act as an honest merge worker",
		Run:   doMergeHonest,
	}
	mergeWrongCmd = &cobra.Command{
		Use:   "merge-wrong",
		Short: "act as a merge worker that commits wrong result",
		Run:   doMergeWrong,
	}
)

func activateCommonConfig(cmd *cobra.Command, args []string) {
	// This subcommand is used in networks where other nodes are honest or colluding with us.
	// Set this so we don't reject things when we run without real IAS.
	ias.SetSkipVerify()
}

func doComputeHonest(cmd *cobra.Command, args []string) {
	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	defaultIdentity, err := initDefaultIdentity(common.DataDir())
	if err != nil {
		panic(fmt.Sprintf("init default identity failed: %+v", err))
	}

	useMockEpochTime := viper.GetBool(cfgMockEpochTime)
	ht := newHonestTendermint()
	if err = ht.start(defaultIdentity, common.DataDir(), useMockEpochTime); err != nil {
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

	var capabilities *node.Capabilities
	if viper.GetBool(cfgFakeSGX) {
		capabilities = &fakeCapabilitiesSGX
	}
	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Info(), defaultRuntimeID, capabilities, node.RoleComputeWorker); err != nil {
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

	if err = cbc.commitTrees(ctx); err != nil {
		panic(fmt.Sprintf("compute commit trees failed: %+v", err))
	}
	logger.Debug("compute honest: committed storage trees",
		"io_write_log", cbc.ioWriteLog,
		"new_io_root", cbc.newIORoot,
		"state_write_log", cbc.stateWriteLog,
		"new_state_root", cbc.newStateRoot,
	)

	if err = cbc.uploadBatch(ctx, hnss); err != nil {
		panic(fmt.Sprintf("compute upload batch failed: %+v", err))
	}

	var rak signature.Signer
	if viper.GetBool(cfgFakeSGX) {
		rak = fakeRAK
	}
	if err = cbc.createCommitment(defaultIdentity, rak, computeCommittee.EncodedMembersHash()); err != nil {
		panic(fmt.Sprintf("compute create commitment failed: %+v", err))
	}

	if err = cbc.publishToCommittee(ht.service, electionHeight, mergeCommittee, scheduler.Worker, ph, defaultRuntimeID, electionHeight); err != nil {
		panic(fmt.Sprintf("compute publish to committee merge worker failed: %+v", err))
	}
	logger.Debug("compute honest: commitment sent")
}

func doComputeWrong(cmd *cobra.Command, args []string) {
	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	defaultIdentity, err := initDefaultIdentity(common.DataDir())
	if err != nil {
		panic(fmt.Sprintf("init default identity failed: %+v", err))
	}

	useMockEpochTime := viper.GetBool(cfgMockEpochTime)
	ht := newHonestTendermint()
	if err = ht.start(defaultIdentity, common.DataDir(), useMockEpochTime); err != nil {
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

	var capabilities *node.Capabilities
	if viper.GetBool(cfgFakeSGX) {
		capabilities = &fakeCapabilitiesSGX
	}
	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Info(), defaultRuntimeID, capabilities, node.RoleComputeWorker); err != nil {
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
	logger.Debug("compute wrong: compute schedule ok")
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
	logger.Debug("compute wrong: received batch", "bd", cbc.bd)

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
	logger.Debug("compute wrong: committed storage trees",
		"io_write_log", cbc.ioWriteLog,
		"new_io_root", cbc.newIORoot,
		"state_write_log", cbc.stateWriteLog,
		"new_state_root", cbc.newStateRoot,
	)

	if err = cbc.uploadBatch(ctx, hnss); err != nil {
		panic(fmt.Sprintf("compute upload batch failed: %+v", err))
	}

	var rak signature.Signer
	if viper.GetBool(cfgFakeSGX) {
		rak = fakeRAK
	}
	if err = cbc.createCommitment(defaultIdentity, rak, computeCommittee.EncodedMembersHash()); err != nil {
		panic(fmt.Sprintf("compute create commitment failed: %+v", err))
	}

	if err = cbc.publishToCommittee(ht.service, electionHeight, mergeCommittee, scheduler.Worker, ph, defaultRuntimeID, electionHeight); err != nil {
		panic(fmt.Sprintf("compute publish to committee merge worker failed: %+v", err))
	}
	logger.Debug("compute wrong: commitment sent")
}

func doComputeStraggler(cmd *cobra.Command, args []string) {
	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	defaultIdentity, err := initDefaultIdentity(common.DataDir())
	if err != nil {
		panic(fmt.Sprintf("init default identity failed: %+v", err))
	}

	useMockEpochTime := viper.GetBool(cfgMockEpochTime)
	ht := newHonestTendermint()
	if err = ht.start(defaultIdentity, common.DataDir(), useMockEpochTime); err != nil {
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

	var capabilities *node.Capabilities
	if viper.GetBool(cfgFakeSGX) {
		capabilities = &fakeCapabilitiesSGX
	}
	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Info(), defaultRuntimeID, capabilities, node.RoleComputeWorker); err != nil {
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
	logger.Debug("compute straggler: compute schedule ok")

	cbc := newComputeBatchContext()

	if err = cbc.receiveBatch(ph); err != nil {
		panic(fmt.Sprintf("compute receive batch failed: %+v", err))
	}
	logger.Debug("compute straggler: received batch", "bd", cbc.bd)

	logger.Debug("compute straggler: bailing")
}

func doMergeHonest(cmd *cobra.Command, args []string) {
	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	defaultIdentity, err := initDefaultIdentity(common.DataDir())
	if err != nil {
		panic(fmt.Sprintf("init default identity failed: %+v", err))
	}

	useMockEpochTime := viper.GetBool(cfgMockEpochTime)
	ht := newHonestTendermint()
	if err = ht.start(defaultIdentity, common.DataDir(), useMockEpochTime); err != nil {
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

	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Info(), defaultRuntimeID, nil, node.RoleMergeWorker); err != nil {
		panic(fmt.Sprintf("registryRegisterNode: %+v", err))
	}

	electionHeight, err := schedulerNextElectionHeight(ht.service, scheduler.KindCompute)
	if err != nil {
		panic(fmt.Sprintf("scheduler next election height failed: %+v", err))
	}
	mergeCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindMerge, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindMerge, err))
	}
	if err = schedulerCheckScheduled(mergeCommittee, defaultIdentity.NodeSigner.Public(), scheduler.Worker); err != nil {
		panic(fmt.Sprintf("scheduler check scheduled failed: %+v", err))
	}
	logger.Debug("merge honest: merge schedule ok")
	storageCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindStorage, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindStorage, err))
	}

	logger.Debug("merge honest: connecting to storage committee")
	hnss, err := storageConnectToCommittee(ht.service, electionHeight, storageCommittee, scheduler.Worker, defaultIdentity)
	if err != nil {
		panic(fmt.Sprintf("storage connect to committee failed: %+v", err))
	}
	defer storageBroadcastCleanup(hnss)

	mbc := newMergeBatchContext()

	if err = mbc.loadCurrentBlock(ht.service, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("merge load current block failed: %+v", err))
	}

	// Receive 1 committee * 2 commitments per committee.
	if err = mbc.receiveCommitments(ph, 2); err != nil {
		panic(fmt.Sprintf("merge receive commitments failed: %+v", err))
	}
	logger.Debug("merge honest: received commitments", "commitments", mbc.commitments)

	ctx := context.Background()

	// Process merge honestly.
	if err = mbc.process(ctx, hnss); err != nil {
		panic(fmt.Sprintf("merge process failed: %+v", err))
	}
	logger.Debug("merge honest: processed",
		"new_block", mbc.newBlock,
	)

	if err = mbc.createCommitment(defaultIdentity); err != nil {
		panic(fmt.Sprintf("merge create commitment failed: %+v", err))
	}

	if err = mbc.publishToChain(ht.service, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("merge publish to chain failed: %+v", err))
	}
	logger.Debug("merge honest: commitment sent")
}

func doMergeWrong(cmd *cobra.Command, args []string) {
	if err := common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	defaultIdentity, err := initDefaultIdentity(common.DataDir())
	if err != nil {
		panic(fmt.Sprintf("init default identity failed: %+v", err))
	}

	useMockEpochTime := viper.GetBool(cfgMockEpochTime)
	ht := newHonestTendermint()
	if err = ht.start(defaultIdentity, common.DataDir(), useMockEpochTime); err != nil {
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

	if err = registryRegisterNode(ht.service, defaultIdentity, common.DataDir(), fakeAddresses, ph.service.Info(), defaultRuntimeID, nil, node.RoleMergeWorker); err != nil {
		panic(fmt.Sprintf("registryRegisterNode: %+v", err))
	}

	electionHeight, err := schedulerNextElectionHeight(ht.service, scheduler.KindCompute)
	if err != nil {
		panic(fmt.Sprintf("scheduler next election height failed: %+v", err))
	}
	mergeCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindMerge, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindMerge, err))
	}
	if err = schedulerCheckScheduled(mergeCommittee, defaultIdentity.NodeSigner.Public(), scheduler.Worker); err != nil {
		panic(fmt.Sprintf("scheduler check scheduled failed: %+v", err))
	}
	logger.Debug("merge wrong: merge schedule ok")
	storageCommittee, err := schedulerGetCommittee(ht.service, electionHeight, scheduler.KindStorage, defaultRuntimeID)
	if err != nil {
		panic(fmt.Sprintf("scheduler get committee %s failed: %+v", scheduler.KindStorage, err))
	}

	logger.Debug("merge wrong: connecting to storage committee")
	hnss, err := storageConnectToCommittee(ht.service, electionHeight, storageCommittee, scheduler.Worker, defaultIdentity)
	if err != nil {
		panic(fmt.Sprintf("storage connect to committee failed: %+v", err))
	}
	defer storageBroadcastCleanup(hnss)

	mbc := newMergeBatchContext()

	if err = mbc.loadCurrentBlock(ht.service, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("merge load current block failed: %+v", err))
	}

	// Receive 1 committee * 2 commitments per committee.
	if err = mbc.receiveCommitments(ph, 2); err != nil {
		panic(fmt.Sprintf("merge receive commitments failed: %+v", err))
	}
	logger.Debug("merge wrong: received commitments", "commitments", mbc.commitments)

	ctx := context.Background()

	// Process the merge wrong.
	origCommitments := mbc.commitments
	var emptyRoot hash.Hash
	emptyRoot.Empty()
	mbc.commitments = []*commitment.OpenComputeCommitment{
		&commitment.OpenComputeCommitment{
			Body: &commitment.ComputeBody{
				Header: commitment.ComputeResultsHeader{
					IORoot:    emptyRoot,
					StateRoot: mbc.currentBlock.Header.StateRoot,
				},
			},
		},
	}

	if err = mbc.process(ctx, hnss); err != nil {
		panic(fmt.Sprintf("merge process failed: %+v", err))
	}
	logger.Debug("merge wrong: processed",
		"new_block", mbc.newBlock,
	)

	mbc.commitments = origCommitments

	// Sanity check the merge results.
	if mbc.newBlock.Header.IORoot != emptyRoot {
		panic(fmt.Sprintf("merge of empty IO trees should be empty. got %s, expected %s", mbc.newBlock.Header.IORoot, emptyRoot))
	}
	if mbc.newBlock.Header.StateRoot != mbc.currentBlock.Header.StateRoot {
		panic(fmt.Sprintf("merge of identical state trees should be the same. got %s, expected %s", mbc.newBlock.Header.StateRoot, mbc.currentBlock.Header.StateRoot))
	}

	if err = mbc.createCommitment(defaultIdentity); err != nil {
		panic(fmt.Sprintf("merge create commitment failed: %+v", err))
	}

	if err = mbc.publishToChain(ht.service, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("merge publish to chain failed: %+v", err))
	}
	logger.Debug("merge wrong: commitment sent")
}

// Register registers the byzantine sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	byzantineCmd.AddCommand(computeHonestCmd)
	byzantineCmd.AddCommand(computeWrongCmd)
	byzantineCmd.AddCommand(computeStragglerCmd)
	byzantineCmd.AddCommand(mergeHonestCmd)
	byzantineCmd.AddCommand(mergeWrongCmd)
	parentCmd.AddCommand(byzantineCmd)
}

func init() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.Bool(cfgFakeSGX, false, "register with SGX capability")
	fs.Bool(cfgMockEpochTime, false, "use the mock epochtime backend")
	_ = viper.BindPFlags(fs)
	byzantineCmd.PersistentFlags().AddFlagSet(fs)

	byzantineCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(p2p.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(tendermint.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(registration.Flags)
}
