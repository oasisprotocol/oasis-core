// Package runtime implements the runtime registry sub-commands.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

const (
	CfgID              = "runtime.id"
	CfgTEEHardware     = "runtime.tee_hardware"
	CfgGenesisState    = "runtime.genesis.state"
	CfgGenesisRound    = "runtime.genesis.round"
	CfgKind            = "runtime.kind"
	CfgKeyManager      = "runtime.keymanager"
	cfgOutput          = "runtime.genesis.file"
	CfgVersion         = "runtime.version"
	CfgVersionEnclave  = "runtime.version.enclave"
	CfgGovernanceModel = "runtime.governance_model"

	// Executor committee flags.
	CfgExecutorGroupSize         = "runtime.executor.group_size"
	CfgExecutorGroupBackupSize   = "runtime.executor.group_backup_size"
	CfgExecutorAllowedStragglers = "runtime.executor.allowed_stragglers"
	CfgExecutorRoundTimeout      = "runtime.executor.round_timeout"
	CfgExecutorMaxMessages       = "runtime.executor.max_messages"
	CfgExecutorMinPoolSize       = "runtime.executor.min_pool_size"

	// Storage committee flags.
	CfgStorageGroupSize               = "runtime.storage.group_size"
	CfgStorageMinWriteReplication     = "runtime.storage.min_write_replication"
	CfgStorageMaxApplyWriteLogEntries = "runtime.storage.max_apply_write_log_entries"
	CfgStorageMaxApplyOps             = "runtime.storage.max_apply_ops"
	CfgStorageCheckpointInterval      = "runtime.storage.checkpoint_interval"
	CfgStorageCheckpointNumKept       = "runtime.storage.checkpoint_num_kept"
	CfgStorageCheckpointChunkSize     = "runtime.storage.checkpoint_chunk_size"
	CfgStorageMinPoolSize             = "runtime.storage.min_pool_size"

	// Transaction scheduler flags.
	CfgTxnSchedulerAlgorithm         = "runtime.txn_scheduler.algorithm"
	CfgTxnSchedulerBatchFlushTimeout = "runtime.txn_scheduler.flush_timeout"
	CfgTxnSchedulerMaxBatchSize      = "runtime.txn_scheduler.max_batch_size"
	CfgTxnSchedulerMaxBatchSizeBytes = "runtime.txn_scheduler.max_batch_size_bytes"
	CfgTxnSchedulerProposerTimeout   = "runtime.txn_scheduler.proposer_timeout"

	// Admission policy flags.
	CfgAdmissionPolicy                 = "runtime.admission_policy"
	CfgAdmissionPolicyEntityWhitelist  = "runtime.admission_policy_entity_whitelist"
	AdmissionPolicyNameAnyNode         = "any-node"
	AdmissionPolicyNameEntityWhitelist = "entity-whitelist"

	// Staking parameters flags.
	CfgStakingThreshold = "runtime.staking.threshold"

	// List runtimes flags.
	CfgIncludeSuspended = "include_suspended"

	runtimeGenesisFilename = "runtime_genesis.json"
)

var (
	outputFlags      = flag.NewFlagSet("", flag.ContinueOnError)
	runtimeFlags     = flag.NewFlagSet("", flag.ContinueOnError)
	runtimeListFlags = flag.NewFlagSet("", flag.ContinueOnError)
	registerFlags    = flag.NewFlagSet("", flag.ContinueOnError)

	runtimeCmd = &cobra.Command{
		Use:   "runtime",
		Short: "runtime registry backend utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init_genesis",
		Short: "initialize a runtime for genesis",
		Run:   doInitGenesis,
	}

	registerCmd = &cobra.Command{
		Use:   "gen_register",
		Short: "generate a register runtime transaction",
		Run:   doGenRegister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered runtimes",
		Run:   doList,
	}

	logger = logging.GetLogger("cmd/registry/runtime")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, registry.Backend) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := registry.NewRegistryClient(conn)
	return conn, client
}

func doInitGenesis(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdCommon.DataDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		os.Exit(1)
	}

	rt, err := runtimeFromFlags()
	if err != nil {
		os.Exit(1)
	}

	// Write out the runtime registration.
	b, _ := json.Marshal(rt)
	if err = ioutil.WriteFile(filepath.Join(dataDir, viper.GetString(cfgOutput)), b, 0o600); err != nil {
		logger.Error("failed to write runtime genesis registration",
			"err", err,
		)
		os.Exit(1)
	}

	logger.Info("generated runtime",
		"runtime", rt.ID,
	)
}

func doGenRegister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	cmdConsensus.InitGenesis()
	cmdConsensus.AssertTxFileOK()

	rt, err := runtimeFromFlags()
	if err != nil {
		logger.Info("failed to get runtime",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := registry.NewRegisterRuntimeTx(nonce, fee, rt)

	cmdConsensus.SignAndSaveTx(context.Background(), tx, nil)
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	query := &registry.GetRuntimesQuery{
		Height:           consensus.HeightLatest,
		IncludeSuspended: viper.GetBool(CfgIncludeSuspended),
	}
	runtimes, err := client.GetRuntimes(context.Background(), query)
	if err != nil {
		logger.Error("failed to query runtimes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, rt := range runtimes {
		var s string
		switch cmdFlags.Verbose() {
		case true:
			b, _ := json.Marshal(rt)
			s = string(b)
		default:
			s = rt.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

func runtimeFromFlags() (*registry.Runtime, error) { // nolint: gocyclo
	var id common.Namespace
	if err := id.UnmarshalHex(viper.GetString(CfgID)); err != nil {
		logger.Error("failed to parse runtime ID",
			"err", err,
		)
		return nil, err
	}

	var teeHardware node.TEEHardware
	s := viper.GetString(CfgTEEHardware)
	if err := teeHardware.FromString(s); err != nil {
		logger.Error("invalid TEE hardware",
			CfgTEEHardware, s,
		)
		return nil, fmt.Errorf("invalid TEE hardware")
	}

	_, signer, err := cmdCommon.LoadEntitySigner()
	if err != nil {
		logger.Error("failed to load owning entity's signer",
			"err", err,
		)
		return nil, err
	}

	var (
		kmID *common.Namespace
		kind registry.RuntimeKind
	)
	s = viper.GetString(CfgKind)
	if err = kind.FromString(s); err != nil {
		logger.Error("invalid runtime kind",
			CfgKind, s,
		)
		return nil, fmt.Errorf("invalid runtime kind")
	}
	switch kind {
	case registry.KindCompute:
		if viper.GetString(CfgKeyManager) != "" {
			var tmpKmID common.Namespace
			if err = tmpKmID.UnmarshalHex(viper.GetString(CfgKeyManager)); err != nil {
				logger.Error("failed to parse key manager ID",
					"err", err,
				)
				return nil, err
			}
			kmID = &tmpKmID
		}
		if id.IsKeyManager() {
			logger.Error("runtime ID has the key manager flag set",
				"id", id,
			)
			return nil, fmt.Errorf("invalid runtime flags")
		}
	case registry.KindKeyManager:
		// Key managers don't have their own key manager.
		if !id.IsKeyManager() {
			logger.Error("runtime ID does not have the key manager flag set",
				"id", id,
			)
			return nil, fmt.Errorf("invalid runtime flags")
		}
	case registry.KindInvalid:
		return nil, fmt.Errorf("cannot create runtime with invalid kind")
	}

	// TODO: Support root upload when registering.
	gen := registry.RuntimeGenesis{}
	gen.Round = viper.GetUint64(CfgGenesisRound)
	switch state := viper.GetString(CfgGenesisState); state {
	case "":
		gen.StateRoot.Empty()
	default:
		var b []byte
		b, err = ioutil.ReadFile(state)
		if err != nil {
			logger.Error("failed to load runtime genesis storage state",
				"err", err,
				"filename", state,
			)
			return nil, err
		}

		var log storage.WriteLog
		if err = json.Unmarshal(b, &log); err != nil {
			logger.Error("failed to parse runtime genesis storage state",
				"err", err,
				"filename", state,
			)
			return nil, err
		}

		// Use in-memory MKVS tree to calculate the new root.
		tree := mkvs.New(nil, nil)
		ctx := context.Background()
		for _, logEntry := range log {
			err = tree.Insert(ctx, logEntry.Key, logEntry.Value)
			if err != nil {
				logger.Error("failed to apply runtime genesis storage state",
					"err", err,
					"filename", state,
				)
				return nil, err
			}
		}

		var newRoot hash.Hash
		_, newRoot, err = tree.Commit(ctx, id, gen.Round)
		if err != nil {
			logger.Error("failed to apply runtime genesis storage state",
				"err", err,
				"filename", state,
			)
			return nil, err
		}

		gen.StateRoot = newRoot
		gen.State = log
	}

	var govModel registry.RuntimeGovernanceModel
	if err = govModel.UnmarshalText([]byte(strings.ToLower(viper.GetString(CfgGovernanceModel)))); err != nil {
		logger.Error("invalid runtime governance model specified")
		return nil, err
	}

	rt := &registry.Runtime{
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          id,
		EntityID:    signer.Public(),
		Genesis:     gen,
		Kind:        kind,
		TEEHardware: teeHardware,
		Version: registry.VersionInfo{
			Version: version.FromU64(viper.GetUint64(CfgVersion)),
		},
		KeyManager: kmID,
		Executor: registry.ExecutorParameters{
			GroupSize:         viper.GetUint64(CfgExecutorGroupSize),
			GroupBackupSize:   viper.GetUint64(CfgExecutorGroupBackupSize),
			AllowedStragglers: viper.GetUint64(CfgExecutorAllowedStragglers),
			RoundTimeout:      viper.GetInt64(CfgExecutorRoundTimeout),
			MaxMessages:       viper.GetUint32(CfgExecutorMaxMessages),
			MinPoolSize:       viper.GetUint64(CfgExecutorMinPoolSize),
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			Algorithm:         viper.GetString(CfgTxnSchedulerAlgorithm),
			BatchFlushTimeout: viper.GetDuration(CfgTxnSchedulerBatchFlushTimeout),
			MaxBatchSize:      viper.GetUint64(CfgTxnSchedulerMaxBatchSize),
			MaxBatchSizeBytes: uint64(viper.GetSizeInBytes(CfgTxnSchedulerMaxBatchSizeBytes)),
			ProposerTimeout:   viper.GetInt64(CfgTxnSchedulerProposerTimeout),
		},
		Storage: registry.StorageParameters{
			GroupSize:               viper.GetUint64(CfgStorageGroupSize),
			MinWriteReplication:     viper.GetUint64(CfgStorageMinWriteReplication),
			MaxApplyWriteLogEntries: viper.GetUint64(CfgStorageMaxApplyWriteLogEntries),
			MaxApplyOps:             viper.GetUint64(CfgStorageMaxApplyOps),
			CheckpointInterval:      viper.GetUint64(CfgStorageCheckpointInterval),
			CheckpointNumKept:       viper.GetUint64(CfgStorageCheckpointNumKept),
			CheckpointChunkSize:     uint64(viper.GetSizeInBytes(CfgStorageCheckpointChunkSize)),
			MinPoolSize:             viper.GetUint64(CfgStorageMinPoolSize),
		},
		GovernanceModel: govModel,
	}
	if teeHardware == node.TEEHardwareIntelSGX {
		var cs sgx.Constraints
		for _, v := range viper.GetStringSlice(CfgVersionEnclave) {
			var enclaveID sgx.EnclaveIdentity
			if err = enclaveID.UnmarshalHex(v); err != nil {
				logger.Error("failed to parse SGX enclave identity",
					"err", err,
				)
				return nil, err
			}
			cs.Enclaves = append(cs.Enclaves, enclaveID)
		}
		rt.Version.TEE = cbor.Marshal(cs)
	}
	switch sap := viper.GetString(CfgAdmissionPolicy); sap {
	case AdmissionPolicyNameAnyNode:
		rt.AdmissionPolicy.AnyNode = &registry.AnyNodeRuntimeAdmissionPolicy{}
	case AdmissionPolicyNameEntityWhitelist:
		entities := make(map[signature.PublicKey]registry.EntityWhitelistConfig)
		for _, se := range viper.GetStringSlice(CfgAdmissionPolicyEntityWhitelist) {
			var e signature.PublicKey
			if err = e.UnmarshalText([]byte(se)); err != nil {
				logger.Error("failed to parse entity ID",
					"err", err,
					CfgAdmissionPolicyEntityWhitelist, se,
				)
				return nil, fmt.Errorf("entity whitelist runtime admission policy parse entity ID: %w", err)
			}
			entities[e] = registry.EntityWhitelistConfig{
				MaxNodes: make(map[node.RolesMask]uint16),
			}
			// TODO: Handle the clusterfuck of parsing the nested map from
			// command-line arguments sometime later.  As it is now, it's
			// configured as unlimited nodes of any role for the given entity.
		}
		rt.AdmissionPolicy.EntityWhitelist = &registry.EntityWhitelistRuntimeAdmissionPolicy{
			Entities: entities,
		}
	default:
		logger.Error("invalid runtime admission policy",
			CfgAdmissionPolicy, sap,
		)
		return nil, fmt.Errorf("invalid runtime admission policy")
	}

	// Staking parameters.
	if th := viper.GetStringMapString(CfgStakingThreshold); th != nil {
		rt.Staking.Thresholds = make(map[staking.ThresholdKind]quantity.Quantity)
		for kindRaw, valueRaw := range th {
			var (
				kind  staking.ThresholdKind
				value quantity.Quantity
			)

			if err = kind.UnmarshalText([]byte(kindRaw)); err != nil {
				return nil, fmt.Errorf("staking: bad threshold kind (%s): %w", kindRaw, err)
			}
			if err = value.UnmarshalText([]byte(valueRaw)); err != nil {
				return nil, fmt.Errorf("staking: bad threshold value (%s): %w", valueRaw, err)
			}

			if _, ok := rt.Staking.Thresholds[kind]; ok {
				return nil, fmt.Errorf("staking: duplicate value for threshold '%s'", kind)
			}
			rt.Staking.Thresholds[kind] = value
		}
	}

	// Validate descriptor.
	if err = rt.ValidateBasic(true); err != nil {
		return nil, fmt.Errorf("invalid runtime descriptor: %w", err)
	}

	return rt, nil
}

// Register registers the runtime sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		initGenesisCmd,
		registerCmd,
		listCmd,
	} {
		runtimeCmd.AddCommand(v)
	}

	for _, v := range []*cobra.Command{
		initGenesisCmd,
		registerCmd,
	} {
		v.Flags().AddFlagSet(cmdFlags.DebugTestEntityFlags)
	}

	initGenesisCmd.Flags().AddFlagSet(runtimeFlags)
	initGenesisCmd.Flags().AddFlagSet(outputFlags)

	listCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	listCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)
	listCmd.Flags().AddFlagSet(runtimeListFlags)

	registerCmd.Flags().AddFlagSet(registerFlags)

	registerCmd.Flags().AddFlagSet(runtimeFlags)

	parentCmd.AddCommand(runtimeCmd)
}

func init() {
	outputFlags.String(cfgOutput, runtimeGenesisFilename, "File name of the document to be written under datadir")
	_ = viper.BindPFlags(outputFlags)

	runtimeFlags.String(CfgID, "", "Runtime ID")
	runtimeFlags.String(CfgTEEHardware, "invalid", "Type of TEE hardware.  Supported values are \"invalid\" and \"intel-sgx\"")
	runtimeFlags.String(CfgGenesisState, "", "Runtime state at genesis")
	runtimeFlags.Uint64(CfgGenesisRound, 0, "Runtime round at genesis")
	runtimeFlags.String(CfgKeyManager, "", "Key Manager Runtime ID")
	runtimeFlags.String(CfgKind, "compute", "Kind of runtime.  Supported values are \"compute\" and \"keymanager\"")
	runtimeFlags.String(CfgVersion, "", "Runtime version. Value is 64-bit hex e.g. 0x0000000100020003 for 1.2.3")
	runtimeFlags.StringSlice(CfgVersionEnclave, nil, "Runtime TEE enclave version(s)")
	runtimeFlags.String(CfgGovernanceModel, "entity", "Runtime governance model (entity or runtime or consensus)")

	// Init Executor committee flags.
	runtimeFlags.Uint64(CfgExecutorGroupSize, 1, "Number of workers in the runtime executor group/committee")
	runtimeFlags.Uint64(CfgExecutorGroupBackupSize, 0, "Number of backup workers in the runtime executor group/committee")
	runtimeFlags.Uint64(CfgExecutorAllowedStragglers, 0, "Number of stragglers allowed per round in the runtime executor group")
	runtimeFlags.Int64(CfgExecutorRoundTimeout, 5, "Executor committee round timeout for this runtime (in consensus blocks)")
	runtimeFlags.Uint32(CfgExecutorMaxMessages, 32, "Maximum number of runtime messages that can be emitted in a round")
	runtimeFlags.Uint64(CfgExecutorMinPoolSize, 1, "Minimum required candidate compute node pool size (should be >= GroupSize+GroupBackupSize)")

	// Init Transaction scheduler flags.
	runtimeFlags.String(CfgTxnSchedulerAlgorithm, registry.TxnSchedulerSimple, "Transaction scheduling algorithm")
	runtimeFlags.Duration(CfgTxnSchedulerBatchFlushTimeout, 1*time.Second, "Maximum amount of time to wait for a scheduled batch")
	runtimeFlags.Uint64(CfgTxnSchedulerMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
	runtimeFlags.String(CfgTxnSchedulerMaxBatchSizeBytes, "16mb", "Maximum size (in bytes) of a batch of runtime requests")
	runtimeFlags.Int64(CfgTxnSchedulerProposerTimeout, 5, "Timeout (in consensus blocks) before a round can be timeouted due to proposer not proposing")

	// Init Storage committee flags.
	runtimeFlags.Uint64(CfgStorageGroupSize, 1, "Number of storage nodes for the runtime")
	runtimeFlags.Uint64(CfgStorageMinWriteReplication, 1, "Minimum required storage write replication")
	runtimeFlags.Uint64(CfgStorageMaxApplyWriteLogEntries, 100_000, "Maximum number of write log entries")
	runtimeFlags.Uint64(CfgStorageMaxApplyOps, 2, "Maximum number of apply operations in a batch")
	runtimeFlags.Uint64(CfgStorageCheckpointInterval, 10_000, "Storage checkpoint interval (in rounds)")
	runtimeFlags.Uint64(CfgStorageCheckpointNumKept, 2, "Number of storage checkpoints to keep")
	runtimeFlags.String(CfgStorageCheckpointChunkSize, "8mb", "Storage checkpoint chunk size")
	runtimeFlags.Uint64(CfgStorageMinPoolSize, 1, "Minimum required candidate storage node pool size (should be >= GroupSize)")

	// Init Admission policy flags.
	runtimeFlags.String(CfgAdmissionPolicy, "", "What type of node admission policy to have")
	runtimeFlags.StringSlice(CfgAdmissionPolicyEntityWhitelist, nil, "For entity whitelist node admission policies, the IDs (hex) of the entities in the whitelist")

	// Init Staking flags.
	runtimeFlags.StringToString(CfgStakingThreshold, nil, "Additional staking threshold for this runtime (<kind>=<value>)")

	_ = viper.BindPFlags(runtimeFlags)
	runtimeFlags.AddFlagSet(cmdSigner.Flags)
	runtimeFlags.AddFlagSet(cmdSigner.CLIFlags)

	registerFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	registerFlags.AddFlagSet(cmdConsensus.TxFlags)
	registerFlags.AddFlagSet(cmdFlags.AssumeYesFlag)

	// List Runtimes flags.
	runtimeListFlags.Bool(CfgIncludeSuspended, false, "Use to include suspended runtimes")
	_ = viper.BindPFlags(runtimeListFlags)
}
