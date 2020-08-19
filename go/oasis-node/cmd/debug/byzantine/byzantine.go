package byzantine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
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
	// CfgSchedulerRoleExpected configures if the executor scheduler role is expected.
	CfgSchedulerRoleExpected = "scheduler_role_expected"
	// CfgExecutorMode configures the byzantine executor mode.
	CfgExecutorMode = "executor_mode"
	// CfgBeaconMode configures the byzantine beacon mode.
	CfgBeaconMode = "beacon_mode"
)

// ExecutorMode represents the byzantine executor mode.
type ExecutorMode uint32

// Executor modes.
const (
	ModeExecutorHonest            ExecutorMode = 0
	ModeExecutorWrong             ExecutorMode = 1
	ModeExecutorStraggler         ExecutorMode = 2
	ModeExecutorFailureIndicating ExecutorMode = 3

	modeExecutorHonestString            = "executor_honest"
	modeExecutorWrongString             = "executor_wrong"
	modeExecutorStragglerString         = "executor_straggler"
	modeExecutorFailureIndicatingString = "executor_failure_indicating"
)

// String returns a string representation of a executor mode.
func (m ExecutorMode) String() string {
	switch m {
	case ModeExecutorHonest:
		return modeExecutorHonestString
	case ModeExecutorWrong:
		return modeExecutorWrongString
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
	case modeExecutorWrongString:
		*m = ModeExecutorWrong
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
	executorHonestCmd = &cobra.Command{
		Use:   "executor",
		Short: "act as an honest executor worker",
		Run:   doExecutorScenario,
	}
	storageCmd = &cobra.Command{
		Use:   "storage",
		Short: "act as a storage worker",
		Run:   doStorageScenario,
	}
	beaconCmd = &cobra.Command{
		Use:   "beacon",
		Short: "act as a validator (for beacon testing)",
		Run:   doBeaconScenario,
	}
)

func activateCommonConfig(cmd *cobra.Command, args []string) {
	// This subcommand is used in networks where other nodes are honest or colluding with us.
	// Set this so we don't reject things when we run without real IAS.
	ias.SetSkipVerify()
	ias.SetAllowDebugEnclaves()
}

func doStorageScenario(cmd *cobra.Command, args []string) {
	b, err := initializeAndRegisterByzantineNode(node.RoleStorageWorker, scheduler.RoleWorker, scheduler.RoleInvalid, false, false)
	if err != nil {
		panic(fmt.Sprintf("error initializing node: %+v", err))
	}
	defer func() {
		_ = b.stop()
	}()

	// Serve storage request for the next 120 seconds, then exit.
	time.Sleep(120 * time.Second)
}

func doExecutorScenario(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Validate executor mode.
	var executorMode ExecutorMode
	if err := executorMode.FromString(viper.GetString(CfgExecutorMode)); err != nil {
		panic(err)
	}

	isTxScheduler := viper.GetBool(CfgSchedulerRoleExpected)
	b, err := initializeAndRegisterByzantineNode(node.RoleComputeWorker, scheduler.RoleInvalid, scheduler.RoleWorker, isTxScheduler, false)
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

	cbc := newComputeBatchContext()
	switch isTxScheduler {
	case true:
		var cont bool
		cont, err = b.receiveAndScheduleTransactions(ctx, cbc, executorMode)
		if err != nil {
			panic(fmt.Sprintf("comptue transaction scheduling failed: %+v", err))
		}
		if !cont {
			return
		}
	case false:
		// If we are not the scheduler, receive the proposed batch.
		if err = cbc.receiveBatch(b.p2p); err != nil {
			panic(fmt.Sprintf("compute receive batch failed: %+v", err))
		}
		logger.Debug("executor: received batch", "bd", cbc.bd)
	}

	if err = cbc.openTrees(ctx, b.storageClients[0]); err != nil {
		panic(fmt.Sprintf("compute open trees failed: %+v", err))
	}
	defer cbc.closeTrees()

	switch executorMode {
	case ModeExecutorHonest:
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
	case ModeExecutorWrong:
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

	if err = cbc.uploadBatch(ctx, b.storageClients); err != nil {
		panic(fmt.Sprintf("compute upload batch failed: %+v", err))
	}
	switch executorMode {
	case ModeExecutorFailureIndicating:
		if err = cbc.createCommitment(b.identity, b.rak, b.executorCommittee.EncodedMembersHash(), commitment.FailureUnknown); err != nil {
			panic(fmt.Sprintf("compute create commitment failed: %+v", err))
		}
	default:
		if err = cbc.createCommitment(b.identity, b.rak, b.executorCommittee.EncodedMembersHash(), commitment.FailureNone); err != nil {
			panic(fmt.Sprintf("compute create commitment failed: %+v", err))
		}

	}

	if err = cbc.publishToChain(b.tendermint.service, b.identity, defaultRuntimeID); err != nil {
		panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
	}
	logger.Debug("executor: commitment sent")
}

// Register registers the byzantine sub-command and all of its children.
func Register(parentCmd *cobra.Command) {
	byzantineCmd.AddCommand(executorHonestCmd)
	byzantineCmd.AddCommand(storageCmd)
	byzantineCmd.AddCommand(beaconCmd)
	parentCmd.AddCommand(byzantineCmd)
}

func init() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.Bool(CfgFakeSGX, false, "register with SGX capability")
	fs.String(CfgVersionFakeEnclaveID, "", "fake runtime enclave identity")
	fs.Uint64(CfgActivationEpoch, 0, "epoch at which the Byzantine node should activate")
	fs.Bool(CfgSchedulerRoleExpected, false, "is executor node expected to be scheduler or not")
	fs.String(CfgExecutorMode, ModeExecutorHonest.String(), "configures executor mode")
	fs.String(CfgBeaconMode, ModeBeaconHonest.String(), "configures beacon mode")
	_ = viper.BindPFlags(fs)
	byzantineCmd.PersistentFlags().AddFlagSet(fs)

	storageFlags.Uint64(CfgNumStorageFailApplyBatch, 0, "Number of ApplyBatch requests to fail")
	storageFlags.Uint64(CfgNumStorageFailApply, 0, "Number of Apply requests to fail")
	storageFlags.Bool(CfgFailReadRequests, false, "If storage worker should fail read requests")
	_ = viper.BindPFlags(storageFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(storageFlags)

	byzantineCmd.PersistentFlags().AddFlagSet(metrics.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.DebugDontBlameOasisFlag)
	byzantineCmd.PersistentFlags().AddFlagSet(flags.DebugTestEntityFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(grpc.ServerLocalFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(grpc.ServerTCPFlags)
	byzantineCmd.PersistentFlags().AddFlagSet(p2p.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(tendermint.Flags)
	byzantineCmd.PersistentFlags().AddFlagSet(registration.Flags)
}
