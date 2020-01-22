// Package runtime implements the runtime registry sub-commands.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/version"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
)

const (
	CfgID             = "runtime.id"
	CfgTEEHardware    = "runtime.tee_hardware"
	CfgGenesisState   = "runtime.genesis.state"
	CfgGenesisRound   = "runtime.genesis.round"
	CfgKind           = "runtime.kind"
	CfgKeyManager     = "runtime.keymanager"
	cfgOutput         = "runtime.genesis.file"
	CfgVersion        = "runtime.version"
	CfgVersionEnclave = "runtime.version.enclave"

	// Executor committee flags.
	CfgExecutorGroupSize         = "runtime.executor.group_size"
	CfgExecutorGroupBackupSize   = "runtime.executor.group_backup_size"
	CfgExecutorAllowedStragglers = "runtime.executor.allowed_stragglers"
	CfgExecutorRoundTimeout      = "runtime.executor.round_timeout"

	// Merge committee flags.
	CfgMergeGroupSize         = "runtime.merge.group_size"
	CfgMergeGroupBackupSize   = "runtime.merge.group_backup_size"
	CfgMergeAllowedStragglers = "runtime.merge.allowed_stragglers"
	CfgMergeRoundTimeout      = "runtime.merge.round_timeout"

	// Storage committee flags.
	CfgStorageGroupSize = "runtime.storage.group_size"

	// Transaction scheduler flags.
	CfgTxnSchedulerGroupSize         = "runtime.txn_scheduler.group_size"
	CfgTxnSchedulerAlgorithm         = "runtime.txn_scheduler.algorithm"
	CfgTxnSchedulerBatchFlushTimeout = "runtime.txn_scheduler.flush_timeout"
	CfgTxnSchedulerMaxBatchSize      = "runtime.txn_scheduler.batching.max_batch_size"
	CfgTxnSchedulerMaxBatchSizeBytes = "runtime.txn_scheduler.batching.max_batch_size_bytes"

	// Admission policy flags.
	CfgAdmissionPolicy                = "runtime.admission_policy"
	CfgAdmissionPolicyEntityWhitelist = "runtime.admission_policy_entity_whitelist"

	runtimeGenesisFilename = "runtime_genesis.json"
)

var (
	outputFlags   = flag.NewFlagSet("", flag.ContinueOnError)
	runtimeFlags  = flag.NewFlagSet("", flag.ContinueOnError)
	registerFlags = flag.NewFlagSet("", flag.ContinueOnError)

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

	rt, signer, err := runtimeFromFlags()
	if err != nil {
		os.Exit(1)
	}

	signed, err := signForRegistration(rt, signer, true)
	if err != nil {
		os.Exit(1)
	}

	// Write out the signed runtime registration.
	b, _ := json.Marshal(signed)
	if err = ioutil.WriteFile(filepath.Join(dataDir, viper.GetString(cfgOutput)), b, 0600); err != nil {
		logger.Error("failed to write signed runtime genesis registration",
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

	rt, signer, err := runtimeFromFlags()
	if err != nil {
		logger.Info("failed to get runtime",
			"err", err,
		)
		os.Exit(1)
	}

	signed, err := signForRegistration(rt, signer, false)
	if err != nil {
		logger.Info("failed to sign runtime descriptor",
			"err", err,
		)
		os.Exit(1)
	}

	nonce, fee := cmdConsensus.GetTxNonceAndFee()
	tx := registry.NewRegisterRuntimeTx(nonce, fee, signed)

	cmdConsensus.SignAndSaveTx(tx)
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	runtimes, err := client.GetRuntimes(context.Background(), consensus.HeightLatest)
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
			b, _ := json.Marshal(&rt)
			s = string(b)
		default:
			s = rt.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

func runtimeFromFlags() (*registry.Runtime, signature.Signer, error) {
	var id common.Namespace
	if err := id.UnmarshalHex(viper.GetString(CfgID)); err != nil {
		logger.Error("failed to parse runtime ID",
			"err", err,
		)
		return nil, nil, err
	}

	var teeHardware node.TEEHardware
	s := viper.GetString(CfgTEEHardware)
	if err := teeHardware.FromString(s); err != nil {
		logger.Error("invalid TEE hardware",
			CfgTEEHardware, s,
		)
		return nil, nil, fmt.Errorf("invalid TEE hardware")
	}

	_, signer, err := loadEntity(cmdFlags.Signer())
	if err != nil {
		logger.Error("failed to load owning entity",
			"err", err,
		)
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("invalid runtime kind")
	}
	switch kind {
	case registry.KindCompute:
		if viper.IsSet(CfgKeyManager) {
			var tmpKmID common.Namespace
			if err = tmpKmID.UnmarshalHex(viper.GetString(CfgKeyManager)); err != nil {
				logger.Error("failed to parse key manager ID",
					"err", err,
				)
				return nil, nil, err
			}
			kmID = &tmpKmID
		}
		if id.IsKeyManager() {
			logger.Error("runtime ID has the key manager flag set",
				"id", id,
			)
			return nil, nil, fmt.Errorf("invalid runtime flags")
		}
	case registry.KindKeyManager:
		// Key managers don't have their own key manager.
		if !id.IsKeyManager() {
			logger.Error("runtime ID does not have the key manager flag set",
				"id", id,
			)
			return nil, nil, fmt.Errorf("invalid runtime flags")
		}
	case registry.KindInvalid:
		return nil, nil, fmt.Errorf("cannot create runtime with invalid kind")
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
			return nil, nil, err
		}

		var log storage.WriteLog
		if err = json.Unmarshal(b, &log); err != nil {
			logger.Error("failed to parse runtime genesis storage state",
				"err", err,
				"filename", state,
			)
			return nil, nil, err
		}

		// Use in-memory Urkel tree to calculate the new root.
		tree := urkel.New(nil, nil)
		ctx := context.Background()
		for _, logEntry := range log {
			err = tree.Insert(ctx, logEntry.Key, logEntry.Value)
			if err != nil {
				logger.Error("failed to apply runtime genesis storage state",
					"err", err,
					"filename", state,
				)
				return nil, nil, err
			}
		}

		var ns common.Namespace
		copy(ns[:], id[:])
		var newRoot hash.Hash
		_, newRoot, err = tree.Commit(ctx, ns, 0)
		if err != nil {
			logger.Error("failed to apply runtime genesis storage state",
				"err", err,
				"filename", state,
			)
			return nil, nil, err
		}

		gen.StateRoot = newRoot
		gen.State = log
	}

	rt := &registry.Runtime{
		ID:          id,
		Genesis:     gen,
		Kind:        kind,
		TEEHardware: teeHardware,
		Version: registry.VersionInfo{
			Version: version.FromU64(viper.GetUint64(CfgVersion)),
		},
		KeyManager: kmID,
		Executor: registry.ExecutorParameters{
			GroupSize:         uint64(viper.GetInt64(CfgExecutorGroupSize)),
			GroupBackupSize:   uint64(viper.GetInt64(CfgExecutorGroupBackupSize)),
			AllowedStragglers: uint64(viper.GetInt64(CfgExecutorAllowedStragglers)),
			RoundTimeout:      viper.GetDuration(CfgExecutorRoundTimeout),
		},
		Merge: registry.MergeParameters{
			GroupSize:         uint64(viper.GetInt64(CfgMergeGroupSize)),
			GroupBackupSize:   uint64(viper.GetInt64(CfgMergeGroupBackupSize)),
			AllowedStragglers: uint64(viper.GetInt64(CfgMergeAllowedStragglers)),
			RoundTimeout:      viper.GetDuration(CfgMergeRoundTimeout),
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			GroupSize:         uint64(viper.GetInt64(CfgTxnSchedulerGroupSize)),
			Algorithm:         viper.GetString(CfgTxnSchedulerAlgorithm),
			BatchFlushTimeout: viper.GetDuration(CfgTxnSchedulerBatchFlushTimeout),
			MaxBatchSize:      viper.GetUint64(CfgTxnSchedulerMaxBatchSize),
			MaxBatchSizeBytes: uint64(viper.GetSizeInBytes(CfgTxnSchedulerMaxBatchSizeBytes)),
		},
		Storage: registry.StorageParameters{GroupSize: uint64(viper.GetInt64(CfgStorageGroupSize))},
	}
	if teeHardware == node.TEEHardwareIntelSGX {
		var vi registry.VersionInfoIntelSGX
		for _, v := range viper.GetStringSlice(CfgVersionEnclave) {
			var enclaveID sgx.EnclaveIdentity
			if err = enclaveID.UnmarshalHex(v); err != nil {
				logger.Error("failed to parse SGX enclave identity",
					"err", err,
				)
				return nil, nil, err
			}
			vi.Enclaves = append(vi.Enclaves, enclaveID)
		}
		rt.Version.TEE = cbor.Marshal(vi)
	}
	switch sap := viper.GetString(CfgAdmissionPolicy); sap {
	case "any-node":
		rt.AdmissionPolicy.AnyNode = &registry.AnyNodeRuntimeAdmissionPolicy{}
	case "entity-whitelist":
		entities := make(map[signature.PublicKey]bool)
		for _, se := range viper.GetStringSlice(CfgAdmissionPolicyEntityWhitelist) {
			var e signature.PublicKey
			if err = e.UnmarshalHex(se); err != nil {
				logger.Error("failed to parse entity ID",
					"err", err,
					CfgAdmissionPolicyEntityWhitelist, se,
				)
				return nil, nil, fmt.Errorf("entity whitelist runtime admission policy parse entity ID: %w", err)
			}
			entities[e] = true
		}
		rt.AdmissionPolicy.EntityWhitelist = &registry.EntityWhitelistRuntimeAdmissionPolicy{
			Entities: entities,
		}
	default:
		logger.Error("invalid runtime admission policy",
			CfgAdmissionPolicy, sap,
		)
		return nil, nil, fmt.Errorf("invalid runtime admission policy")
	}

	return rt, signer, nil
}

func signForRegistration(rt *registry.Runtime, signer signature.Signer, isGenesis bool) (*registry.SignedRuntime, error) {
	var ctx signature.Context
	switch isGenesis {
	case false:
		ctx = registry.RegisterRuntimeSignatureContext
	case true:
		ctx = registry.RegisterGenesisRuntimeSignatureContext
	}

	signed, err := registry.SignRuntime(signer, ctx, rt)
	if err != nil {
		logger.Error("failed to sign runtime descriptor",
			"err", err,
		)
		return nil, err
	}

	return signed, err
}

func loadEntity(dataDir string) (*entity.Entity, signature.Signer, error) {
	if cmdFlags.DebugTestEntity() {
		return entity.TestEntity()
	}

	// TODO/hsm: Configure factory dynamically.
	entitySignerFactory := fileSigner.NewFactory(dataDir, signature.SignerEntity)
	return entity.Load(dataDir, entitySignerFactory)
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

	// Init Executor committee flags.
	runtimeFlags.Uint64(CfgExecutorGroupSize, 1, "Number of workers in the runtime executor group/committee")
	runtimeFlags.Uint64(CfgExecutorGroupBackupSize, 0, "Number of backup workers in the runtime executor group/committee")
	runtimeFlags.Uint64(CfgExecutorAllowedStragglers, 0, "Number of stragglers allowed per round in the runtime executor group")
	runtimeFlags.Duration(CfgExecutorRoundTimeout, 10*time.Second, "Executor committee round timeout for this runtime")

	// Init Merge committee flags.
	runtimeFlags.Uint64(CfgMergeGroupSize, 1, "Number of workers in the runtime merge group/committee")
	runtimeFlags.Uint64(CfgMergeGroupBackupSize, 0, "Number of backup workers in the runtime merge group/committee")
	runtimeFlags.Uint64(CfgMergeAllowedStragglers, 0, "Number of stragglers allowed per round in the runtime merge group")
	runtimeFlags.Duration(CfgMergeRoundTimeout, 10*time.Second, "Merge committee round timeout for this runtime")

	// Init Transaction scheduler flags.
	runtimeFlags.Uint64(CfgTxnSchedulerGroupSize, 1, "Number of transaction scheduler nodes for the runtime")
	runtimeFlags.String(CfgTxnSchedulerAlgorithm, "batching", "Transaction scheduling algorithm")
	runtimeFlags.Duration(CfgTxnSchedulerBatchFlushTimeout, 1*time.Second, "Maximum amount of time to wait for a scheduled batch")
	runtimeFlags.Uint64(CfgTxnSchedulerMaxBatchSize, 1000, "Maximum size of a batch of runtime requests")
	runtimeFlags.String(CfgTxnSchedulerMaxBatchSizeBytes, "16mb", "Maximum size (in bytes) of a batch of runtime requests")

	// Init Storage committee flags.
	runtimeFlags.Uint64(CfgStorageGroupSize, 1, "Number of storage nodes for the runtime")

	// Init Admission policy flags.
	runtimeFlags.String(CfgAdmissionPolicy, "", "What type of node admission policy to have")
	runtimeFlags.StringSlice(CfgAdmissionPolicyEntityWhitelist, nil, "For entity whitelist node admission policies, the IDs (hex) of the entities in the whitelist")

	_ = viper.BindPFlags(runtimeFlags)
	runtimeFlags.AddFlagSet(cmdFlags.SignerFlags)

	registerFlags.AddFlagSet(cmdFlags.DebugTestEntityFlags)
	registerFlags.AddFlagSet(cmdConsensus.TxFlags)
}
