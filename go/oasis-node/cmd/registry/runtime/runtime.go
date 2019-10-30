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
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/version"
	grpcRegistry "github.com/oasislabs/oasis-core/go/grpc/registry"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
)

const (
	cfgID                            = "runtime.id"
	cfgTEEHardware                   = "runtime.tee_hardware"
	cfgReplicaGroupSize              = "runtime.replica_group_size"
	cfgReplicaGroupBackupSize        = "runtime.replica_group_backup_size"
	cfgReplicaAllowedStragglers      = "runtime.replica_allowed_stragglers"
	cfgStorageGroupSize              = "runtime.storage_group_size"
	cfgTransactionSchedulerGroupSize = "runtime.transaction_scheduler_group_size"
	cfgGenesisState                  = "runtime.genesis.state"
	cfgKind                          = "runtime.kind"
	cfgKeyManager                    = "runtime.keymanager"
	cfgOutput                        = "runtime.genesis.file"
	cfgVersion                       = "runtime.version"
	cfgVersionEnclave                = "runtime.version.enclave"

	runtimeGenesisFilename = "runtime_genesis.json"
)

var (
	outputFlags  = flag.NewFlagSet("", flag.ContinueOnError)
	runtimeFlags = flag.NewFlagSet("", flag.ContinueOnError)

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
		Use:   "register",
		Short: "register a runtime",
		Run:   doRegister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered runtimes",
		Run:   doList,
	}

	logger = logging.GetLogger("cmd/registry/runtime")
)

func doConnect(cmd *cobra.Command) (*grpc.ClientConn, grpcRegistry.RuntimeRegistryClient) {
	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}

	client := grpcRegistry.NewRuntimeRegistryClient(conn)

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

func doRegister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	rt, signer, err := runtimeFromFlags()
	if err != nil {
		os.Exit(1)
	}

	nrRetries := cmdFlags.Retries()
	for i := 0; i <= nrRetries; {
		if err := actuallyRegister(cmd, rt, signer); err == nil {
			return
		}

		if nrRetries > 0 {
			i++
		}
		if i <= nrRetries {
			time.Sleep(1 * time.Second)
		}
	}
}

func actuallyRegister(cmd *cobra.Command, rt *registry.Runtime, signer signature.Signer) error {
	conn, client := doConnect(cmd)
	defer conn.Close()

	signed, err := signForRegistration(rt, signer, false)
	if err != nil {
		return err
	}

	req := &grpcRegistry.RegisterRuntimeRequest{
		Runtime: signed.ToProto(),
	}
	if _, err = client.RegisterRuntime(context.Background(), req); err != nil {
		logger.Error("failed to register runtime",
			"err", err,
		)
		return err
	}

	logger.Info("registered runtime",
		"runtime", rt.ID,
	)

	return nil
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	runtimes, err := client.GetRuntimes(context.Background(), &grpcRegistry.RuntimesRequest{Height: 0})
	if err != nil {
		logger.Error("failed to query runtimes",
			"err", err,
		)
		os.Exit(1)
	}

	for _, v := range runtimes.GetRuntime() {
		var rt registry.Runtime
		if err = rt.FromProto(v); err != nil {
			logger.Error("failed to de-serialize runtime",
				"err", err,
				"pb", v,
			)
			continue
		}

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
	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(cfgID)); err != nil {
		logger.Error("failed to parse runtime ID",
			"err", err,
		)
		return nil, nil, err
	}

	var teeHardware node.TEEHardware
	s := viper.GetString(cfgTEEHardware)
	if err := teeHardware.FromString(s); err != nil {
		logger.Error("invalid TEE hardware",
			cfgTEEHardware, s,
		)
		return nil, nil, fmt.Errorf("invalid TEE hardware")
	}

	ent, signer, err := loadEntity(cmdFlags.Entity())
	if err != nil {
		logger.Error("failed to load owning entity",
			"err", err,
		)
		return nil, nil, err
	}

	var (
		kmID signature.PublicKey
		kind registry.RuntimeKind
	)
	s = viper.GetString(cfgKind)
	if err = kind.FromString(s); err != nil {
		logger.Error("invalid runtime kind",
			cfgKind, s,
		)
		return nil, nil, fmt.Errorf("invalid runtime kind")
	}
	switch kind {
	case registry.KindCompute:
		if err = kmID.UnmarshalHex(viper.GetString(cfgKeyManager)); err != nil {
			logger.Error("failed to parse key manager ID",
				"err", err,
			)
			return nil, nil, err
		}
	case registry.KindKeyManager:
		// Key managers don't have their own key manager.
		kmID = id
	}

	// TODO: Support root upload when registering.
	gen := registry.RuntimeGenesis{}
	switch state := viper.GetString(cfgGenesisState); state {
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
			err := tree.Insert(ctx, logEntry.Key, logEntry.Value)
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
		_, newRoot, err := tree.Commit(ctx, ns, 0)
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
		ID:                            id,
		Genesis:                       gen,
		ReplicaGroupSize:              uint64(viper.GetInt64(cfgReplicaGroupSize)),
		ReplicaGroupBackupSize:        uint64(viper.GetInt64(cfgReplicaGroupBackupSize)),
		ReplicaAllowedStragglers:      uint64(viper.GetInt64(cfgReplicaAllowedStragglers)),
		StorageGroupSize:              uint64(viper.GetInt64(cfgStorageGroupSize)),
		TransactionSchedulerGroupSize: uint64(viper.GetInt64(cfgTransactionSchedulerGroupSize)),
		Kind:                          kind,
		TEEHardware:                   teeHardware,
		Version: registry.VersionInfo{
			Version: version.FromU64(viper.GetUint64(cfgVersion)),
		},
		KeyManager:       kmID,
		RegistrationTime: ent.RegistrationTime,
	}
	if teeHardware == node.TEEHardwareIntelSGX {
		var vi registry.VersionInfoIntelSGX
		for _, v := range viper.GetStringSlice(cfgVersionEnclave) {
			var enclaveID sgx.EnclaveIdentity
			if err := enclaveID.UnmarshalHex(v); err != nil {
				logger.Error("failed to parse SGX enclave identity",
					"err", err,
				)
				return nil, nil, err
			}
			vi.Enclaves = append(vi.Enclaves, enclaveID)
		}
		rt.Version.TEE = cbor.Marshal(vi)
	}

	return rt, signer, nil
}

func signForRegistration(rt *registry.Runtime, signer signature.Signer, isGenesis bool) (*registry.SignedRuntime, error) {
	var ctx signature.Context
	switch isGenesis {
	case false:
		ctx = registry.RegisterRuntimeSignatureContext
		rt.RegistrationTime = uint64(time.Now().Unix())
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
		v.Flags().AddFlagSet(cmdFlags.ConsensusBackendFlag)
	}

	initGenesisCmd.Flags().AddFlagSet(runtimeFlags)
	initGenesisCmd.Flags().AddFlagSet(outputFlags)

	listCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	listCmd.Flags().AddFlagSet(cmdFlags.VerboseFlags)

	registerCmd.Flags().AddFlagSet(cmdGrpc.ClientFlags)
	registerCmd.Flags().AddFlagSet(cmdFlags.RetriesFlags)

	registerCmd.Flags().AddFlagSet(runtimeFlags)

	parentCmd.AddCommand(runtimeCmd)
}

func init() {
	outputFlags.String(cfgOutput, runtimeGenesisFilename, "File name of the document to be written under datadir")
	_ = viper.BindPFlags(outputFlags)

	runtimeFlags.String(cfgID, "", "Runtime ID")
	runtimeFlags.String(cfgTEEHardware, "invalid", "Type of TEE hardware.  Supported values are \"invalid\" and \"intel-sgx\"")
	runtimeFlags.Uint64(cfgReplicaGroupSize, 1, "Number of workers in the runtime replica group")
	runtimeFlags.Uint64(cfgReplicaGroupBackupSize, 0, "Number of backup workers in the runtime replica group")
	runtimeFlags.Uint64(cfgReplicaAllowedStragglers, 0, "Number of stragglers allowed per round in the runtime replica group")
	runtimeFlags.Uint64(cfgStorageGroupSize, 1, "Number of storage nodes for the runtime")
	runtimeFlags.Uint64(cfgTransactionSchedulerGroupSize, 1, "Number of transaction scheduler nodes for the runtime")
	runtimeFlags.String(cfgGenesisState, "", "Runtime state at genesis")
	runtimeFlags.String(cfgKeyManager, "", "Key Manager Runtime ID")
	runtimeFlags.String(cfgKind, "compute", "Kind of runtime.  Supported values are \"compute\" and \"keymanager\"")
	runtimeFlags.String(cfgVersion, "", "Runtime version. Value is 64-bit hex e.g. 0x0000000100020003 for 1.2.3")
	runtimeFlags.StringSlice(cfgVersionEnclave, nil, "Runtime TEE enclave version(s)")
	_ = viper.BindPFlags(runtimeFlags)
	runtimeFlags.AddFlagSet(cmdFlags.EntityFlags)
}
