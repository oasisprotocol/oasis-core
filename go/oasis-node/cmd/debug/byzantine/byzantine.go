package byzantine

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	// CfgFakeSGX configures registering with SGX capability.
	CfgFakeSGX = "fake_sgx"
	// CfgRuntimeID configures the runtime ID Byzantine node participates in.
	CfgRuntimeID = "runtime_id"
	// CfgVersionFakeEnclaveID configures runtime's EnclaveIdentity.
	CfgVersionFakeEnclaveID = "runtime.version.fake_enclave_id"
	// CfgActivationEpoch configures the epoch at which the Byzantine node activates.
	CfgActivationEpoch = "activation_epoch"
	// CfgPrimarySchedulerExpected configures whether it is expected for the executor to act
	// as the primary scheduler.
	CfgPrimarySchedulerExpected = "executor.primary_scheduler_expected"
	// CfgExecutorMode configures the byzantine executor mode.
	CfgExecutorMode = "executor.mode"
	// CfgExecutorProposeBogusTx configures whether the executor in scheduler role should propose
	// transactions that nobody else has.
	CfgExecutorProposeBogusTx = "executor.propose_bogus_tx"
	// CfgVRFBeaconMode configures the byzantine VRF beacon mode.
	CfgVRFBeaconMode = "vrf_beacon_mode"

	defaultRuntimeIDHex = "8000000000000000000000000000000000000000000000000000000000000000"
)

// ExecutorMode represents the byzantine executor mode.
type ExecutorMode uint32

// Executor modes.
const (
	ModeExecutorHonest            ExecutorMode = 0
	ModeExecutorDishonest         ExecutorMode = 1
	ModeExecutorRunaway           ExecutorMode = 2
	ModeExecutorStraggler         ExecutorMode = 3
	ModeExecutorFailureIndicating ExecutorMode = 4

	modeExecutorHonestString            = "executor_honest"
	modeExecutorDishonestString         = "executor_dishonest"
	modeExecutorRunawayString           = "executor_runaway"
	modeExecutorStragglerString         = "executor_straggler"
	modeExecutorFailureIndicatingString = "executor_failure_indicating"
)

// String returns a string representation of a executor mode.
func (m ExecutorMode) String() string {
	switch m {
	case ModeExecutorHonest:
		return modeExecutorHonestString
	case ModeExecutorDishonest:
		return modeExecutorDishonestString
	case ModeExecutorRunaway:
		return modeExecutorRunawayString
	case ModeExecutorStraggler:
		return modeExecutorStragglerString
	case ModeExecutorFailureIndicating:
		return modeExecutorFailureIndicatingString
	default:
		return "[unsupported runtime kind]"
	}
}

// FromString deserializes a string into a executor mode.
func (m *ExecutorMode) FromString(str string) error {
	switch strings.ToLower(str) {
	case modeExecutorHonestString:
		*m = ModeExecutorHonest
	case modeExecutorDishonestString:
		*m = ModeExecutorDishonest
	case modeExecutorRunawayString:
		*m = ModeExecutorRunaway
	case modeExecutorStragglerString:
		*m = ModeExecutorStraggler
	case modeExecutorFailureIndicatingString:
		*m = ModeExecutorFailureIndicating
	default:
		return fmt.Errorf("invalid executor mode kind: %s", m)
	}

	return nil
}

var (
	logger       = logging.GetLogger("cmd/byzantine")
	byzantineCmd = &cobra.Command{
		Use:              "byzantine",
		Short:            "run some node behaviors for testing, often not honest",
		PersistentPreRun: activateCommonConfig,
	}
	executorCmd = &cobra.Command{
		Use:   "executor",
		Short: "act as an executor",
		Run:   doExecutorScenario,
	}
	vrfBeaconCmd = &cobra.Command{
		Use:   "vrfbeacon",
		Short: "act as a validator (for VRF beacon testing)",
		Run:   doVRFBeaconScenario,
	}
)

func activateCommonConfig(*cobra.Command, []string) {
	// This subcommand is used in networks where other nodes are honest or colluding with us.
	// Set this so we don't reject things when we run without real IAS.
	ias.SetSkipVerify()
	ias.SetAllowDebugEnclaves()
	pcs.SetSkipVerify()
	pcs.SetAllowDebugEnclaves()
}

func doExecutorScenario(*cobra.Command, []string) { //nolint: gocyclo
	ctx := context.Background()

	var runtimeID common.Namespace
	if err := runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID)); err != nil {
		panic(fmt.Errorf("error initializing node: failed to parse runtime ID: %w", err))
	}

	// Validate executor mode.
	var executorMode ExecutorMode
	if err := executorMode.FromString(viper.GetString(CfgExecutorMode)); err != nil {
		panic(err)
	}

	round := uint64(3)
	isTxScheduler := viper.GetBool(CfgPrimarySchedulerExpected)
	// For every command where applicable you will have to parse yaml config??
	cfg := &config.GlobalConfig
	b, err := initializeAndRegisterByzantineNode(
		cfg,
		runtimeID,
		node.RoleComputeWorker,
		scheduler.RoleWorker,
		isTxScheduler,
		false,
		round,
	)
	if err != nil {
		panic(fmt.Sprintf("error initializing node: %+v", err))
	}
	defer func() {
		_ = b.stop()
	}()

	if executorMode == ModeExecutorStraggler {
		logger.Debug("executor straggler: stopping")
		return
	}

	// Get the latest roothash block.
	var blk *block.Block
	blk, err = getRoothashLatestBlock(ctx, b.cometbft.service, runtimeID)
	if err != nil {
		panic(fmt.Errorf("failed getting latest roothash block: %w", err))
	}
	if blk.Header.Round != round-1 {
		panic(fmt.Errorf("latest roothash block has invalid round (expected %d, got %d)", round-1, blk.Header.Round))
	}

	var schedulerID signature.PublicKey
	cbc := newComputeBatchContext(b.chainContext, runtimeID)
	switch isTxScheduler {
	case true:
		// If we are the transaction scheduler, we wait for transactions and schedule them.
		var cont bool
		cont, err = b.receiveAndScheduleTransactions(ctx, cbc, blk, executorMode)
		if err != nil {
			panic(fmt.Sprintf("compute transaction scheduling failed: %+v", err))
		}
		if !cont {
			return
		}

		schedulerID = b.identity.NodeSigner.Public()
	case false:
		// If we are not the scheduler, receive transactions and the proposal.
		if err = cbc.receiveProposal(b.p2p); err != nil {
			panic(fmt.Sprintf("compute receive proposal failed: %+v", err))
		}
		logger.Debug("executor: received proposal", "proposal", cbc.proposal)

		schedulerID = cbc.proposal.NodeID
	}

	if err = cbc.openTrees(ctx, blk, b.storageClient); err != nil {
		panic(fmt.Sprintf("compute open trees failed: %+v", err))
	}
	defer cbc.closeTrees()

	// Update current epoch to mimic the test key-value runtime.
	var encodedEpoch [8]byte
	binary.BigEndian.PutUint64(encodedEpoch[:], uint64(b.executorCommittee.ValidFor))

	if err = cbc.stateTree.Insert(ctx, []byte{0x02}, encodedEpoch[:]); err != nil {
		panic(fmt.Sprintf("compute state tree set failed: %+v", err))
	}

	switch executorMode {
	case ModeExecutorHonest:
		// Process transaction honestly.
		switch len(cbc.txs) {
		case 0:
			// No transactions, don't modify anything else.
		case 1:
			// A single transaction, simulate the key-value runtime.
			if err = cbc.stateTree.Insert(ctx, []byte("hello_key"), []byte("hello_value")); err != nil {
				panic(fmt.Sprintf("compute state tree set failed: %+v", err))
			}
			if err = cbc.addResultSuccess(ctx, cbc.txs[0], nil, transaction.Tags{
				&transaction.Tag{Key: []byte("kv_op"), Value: []byte("insert")},
				&transaction.Tag{Key: []byte("kv_key"), Value: []byte("hello_key")},
			}); err != nil {
				panic(fmt.Sprintf("compute add result success failed: %+v", err))
			}
		default:
			// Unsupported condition.
			panic(fmt.Sprintf("unsupported number of transactions: %d", len(cbc.txs)))
		}
	case ModeExecutorDishonest:
		// Alter the state incorrectly.
		if err = cbc.stateTree.Insert(ctx, []byte("hello_key"), []byte("wrong")); err != nil {
			panic(fmt.Sprintf("compute state tree set failed: %+v", err))
		}

		switch len(cbc.txs) {
		case 0:
			// No transactions.
		case 1:
			// A single transaction.
			if err = cbc.addResultSuccess(ctx, cbc.txs[0], nil, transaction.Tags{
				&transaction.Tag{Key: []byte("kv_op"), Value: []byte("insert")},
				&transaction.Tag{Key: []byte("kv_key"), Value: []byte("hello_key")},
			}); err != nil {
				panic(fmt.Sprintf("compute add result success failed: %+v", err))
			}
		default:
			// Unsupported condition.
			panic(fmt.Sprintf("unsupported number of transactions: %d", len(cbc.txs)))
		}
	case ModeExecutorFailureIndicating:
		// No need to process anything as we'll submit a failure indicating commitment anyway.
	default:
		// Other modes should have already quit by here.
		panic(fmt.Sprintf("unexpected executor mode: %s", executorMode.String()))
	}

	if err = cbc.commitTrees(ctx); err != nil {
		panic(fmt.Sprintf("compute commit trees failed: %+v", err))
	}
	logger.Debug("executor: committed storage trees",
		"io_write_log", cbc.ioWriteLog,
		"new_io_root", cbc.newIORoot,
		"state_write_log", cbc.stateWriteLog,
		"new_state_root", cbc.newStateRoot,
		"mode", executorMode,
	)

	switch executorMode {
	case ModeExecutorFailureIndicating:
		if err = cbc.createCommitment(b.identity, schedulerID, b.rak, commitment.FailureUnknown); err != nil {
			panic(fmt.Sprintf("compute create commitment failed: %+v", err))
		}
	default:
		if err = cbc.createCommitment(b.identity, schedulerID, b.rak, commitment.FailureNone); err != nil {
			panic(fmt.Sprintf("compute create commitment failed: %+v", err))
		}

	}

	if err = cbc.publishToChain(b.cometbft.service, b.identity); err != nil {
		panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
	}
	logger.Debug("executor: commitment sent")

	// If this is supposed to be a storage node, keep it running forever.
	if viper.GetBool(CfgCorruptGetDiff) {
		select {}
	}
}

// Register registers the byzantine sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	byzantineCmd.AddCommand(executorCmd)
	byzantineCmd.AddCommand(vrfBeaconCmd)
	parentCmd.AddCommand(byzantineCmd)
}

func init() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.Bool(CfgFakeSGX, false, "register with SGX capability")
	fs.String(CfgRuntimeID, defaultRuntimeIDHex, "runtime ID byzantine node participates in")
	fs.String(CfgVersionFakeEnclaveID, "", "fake runtime enclave identity")
	fs.Uint64(CfgActivationEpoch, 0, "epoch at which the Byzantine node should activate")
	fs.Bool(CfgPrimarySchedulerExpected, false, "is executor node expected to be primary scheduler or not")
	fs.String(CfgExecutorMode, ModeExecutorHonest.String(), "configures executor mode")
	fs.Bool(CfgExecutorProposeBogusTx, false, "whether the executor should propose bogus transactions")
	fs.String(CfgVRFBeaconMode, ModeVRFBeaconHonest.String(), "configures VRF beacon mode")
	_ = viper.BindPFlags(fs)
	byzantineCmd.PersistentFlags().AddFlagSet(fs)

	storageFlags.Bool(CfgFailReadRequests, false, "Whether the storage node should fail read requests")
	storageFlags.Bool(CfgCorruptGetDiff, false, "Whether the storage node should corrupt GetDiff responses")
	_ = viper.BindPFlags(storageFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(storageFlags)

	byzantineCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.DebugDontBlameOasisFlag)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.DebugTestEntityFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(grpc.ServerLocalFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(grpc.ServerTCPFlags)
}
