// Package runtime implements the runtime registry sub-commands.
package runtime

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
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
	cfgEntity                        = "entity"

	optKindCompute    = "compute"
	optKindKeyManager = "keymanager"

	runtimeGenesisFilename = "runtime_genesis.json"
)

var (
	runtimeCmd = &cobra.Command{
		Use:   "runtime",
		Short: "runtime registry backend utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init_genesis",
		Short: "initialize a runtime for genesis",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdFlags.RegisterDebugTestEntity(cmd)
			cmdFlags.RegisterConsensusBackend(cmd)
			registerRuntimeFlags(cmd)
			registerOutputFlag(cmd)
		},
		Run: doInitGenesis,
	}

	registerCmd = &cobra.Command{
		Use:   "register",
		Short: "register a runtime",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			cmdFlags.RegisterDebugTestEntity(cmd)
			cmdFlags.RegisterConsensusBackend(cmd)
			cmdFlags.RegisterRetries(cmd)
			registerRuntimeFlags(cmd)
		},
		Run: doRegister,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "list registered runtimes",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			cmdFlags.RegisterVerbose(cmd)
		},
		Run: doList,
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

	rt, privKey, err := runtimeFromFlags()
	if err != nil {
		os.Exit(1)
	}

	signed, err := signForRegistration(rt, privKey, true)
	if err != nil {
		os.Exit(1)
	}

	// Write out the signed runtime registration.
	b := json.Marshal(signed)
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

	rt, privKey, err := runtimeFromFlags()
	if err != nil {
		os.Exit(1)
	}

	nrRetries := cmdFlags.Retries()
	for i := 0; i <= nrRetries; {
		if err := actuallyRegister(cmd, rt, privKey); err == nil {
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

func actuallyRegister(cmd *cobra.Command, rt *registry.Runtime, privKey *signature.PrivateKey) error {
	conn, client := doConnect(cmd)
	defer conn.Close()

	signed, err := signForRegistration(rt, privKey, false)
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
			s = string(json.Marshal(&rt))
		default:
			s = rt.ID.String()
		}

		fmt.Printf("%v\n", s)
	}
}

func runtimeFromFlags() (*registry.Runtime, *signature.PrivateKey, error) {
	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(cfgID)); err != nil {
		logger.Error("failed to parse runtime ID",
			"err", err,
		)
		return nil, nil, err
	}

	var teeHardware node.TEEHardware
	s := viper.GetString(cfgTEEHardware)
	switch strings.ToLower(s) {
	case "invalid":
	case "intel-sgx":
		teeHardware = node.TEEHardwareIntelSGX
	default:
		logger.Error("invalid TEE hardware",
			cfgTEEHardware, s,
		)
		return nil, nil, fmt.Errorf("invalid TEE hardware")
	}

	ent, privKey, err := loadEntity(viper.GetString(cfgEntity))
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
	switch strings.ToLower(s) {
	case optKindCompute:
		if err = kmID.UnmarshalHex(viper.GetString(cfgKeyManager)); err != nil {
			logger.Error("failed to parse key manager ID",
				"err", err,
			)
			return nil, nil, err
		}
	case optKindKeyManager:
		kind = registry.KindKeyManager

		// Key managers don't have their own key manager.
		kmID = id
	default:
		logger.Error("invalid runtime kind",
			cfgKind, s,
		)
		return nil, nil, fmt.Errorf("invalid runtime Kind")
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

	return &registry.Runtime{
		ID:                            id,
		Genesis:                       gen,
		ReplicaGroupSize:              uint64(viper.GetInt64(cfgReplicaGroupSize)),
		ReplicaGroupBackupSize:        uint64(viper.GetInt64(cfgReplicaGroupBackupSize)),
		ReplicaAllowedStragglers:      uint64(viper.GetInt64(cfgReplicaAllowedStragglers)),
		StorageGroupSize:              uint64(viper.GetInt64(cfgStorageGroupSize)),
		TransactionSchedulerGroupSize: uint64(viper.GetInt64(cfgTransactionSchedulerGroupSize)),
		TEEHardware:                   teeHardware,
		KeyManager:                    kmID,
		Kind:                          kind,
		RegistrationTime:              ent.RegistrationTime,
	}, privKey, nil
}

func signForRegistration(rt *registry.Runtime, privKey *signature.PrivateKey, isGenesis bool) (*registry.SignedRuntime, error) {
	var ctx []byte
	switch isGenesis {
	case false:
		ctx = registry.RegisterRuntimeSignatureContext
		rt.RegistrationTime = uint64(time.Now().Unix())
	case true:
		ctx = registry.RegisterGenesisRuntimeSignatureContext
	}

	signed, err := registry.SignRuntime(*privKey, ctx, rt)
	if err != nil {
		logger.Error("failed to sign runtime descriptor",
			"err", err,
		)
		return nil, err
	}

	return signed, err
}

func loadEntity(dataDir string) (*entity.Entity, *signature.PrivateKey, error) {
	if cmdFlags.DebugTestEntity() {
		return entity.TestEntity()
	}

	return entity.Load(dataDir)
}

func registerOutputFlag(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgOutput, runtimeGenesisFilename, "File name of the document to be written under datadir")
	}

	for _, v := range []string{
		cfgOutput,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

func registerRuntimeFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgID, "", "Runtime ID")
		cmd.Flags().String(cfgTEEHardware, "invalid", "Type of TEE hardware.  Supported values are \"invalid\" and \"intel-sgx\"")
		cmd.Flags().Uint64(cfgReplicaGroupSize, 1, "Number of workers in the runtime replica group")
		cmd.Flags().Uint64(cfgReplicaGroupBackupSize, 0, "Number of backup workers in the runtime replica group")
		cmd.Flags().Uint64(cfgReplicaAllowedStragglers, 0, "Number of stragglers allowed per round in the runtime replica group")
		cmd.Flags().Uint64(cfgStorageGroupSize, 1, "Number of storage nodes for the runtime")
		cmd.Flags().Uint64(cfgTransactionSchedulerGroupSize, 1, "Number of transaction scheduler nodes for the runtime")
		cmd.Flags().String(cfgGenesisState, "", "Runtime state at genesis")
		cmd.Flags().String(cfgKeyManager, "", "Key Manager Runtime ID")
		cmd.Flags().String(cfgKind, optKindCompute, "Kind of runtime.  Supported values are \"compute\" and \"keymanager\"")
		cmd.Flags().String(cfgEntity, "", "Path to directory containing entity private key and descriptor")
	}

	for _, v := range []string{
		cfgID,
		cfgTEEHardware,
		cfgReplicaGroupSize,
		cfgReplicaGroupBackupSize,
		cfgReplicaAllowedStragglers,
		cfgStorageGroupSize,
		cfgTransactionSchedulerGroupSize,
		cfgGenesisState,
		cfgKeyManager,
		cfgKind,
		cfgEntity,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
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
		cmdFlags.RegisterDebugTestEntity(v)
		cmdFlags.RegisterConsensusBackend(v)
	}

	registerRuntimeFlags(initGenesisCmd)
	registerOutputFlag(initGenesisCmd)

	cmdGrpc.RegisterClientFlags(listCmd, false)
	cmdFlags.RegisterVerbose(listCmd)

	cmdGrpc.RegisterClientFlags(registerCmd, false)
	cmdFlags.RegisterRetries(registerCmd)
	registerRuntimeFlags(registerCmd)

	parentCmd.AddCommand(runtimeCmd)
}
