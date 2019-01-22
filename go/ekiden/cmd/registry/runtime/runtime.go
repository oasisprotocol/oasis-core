// Package runtime implements the runtime registry sub-commands.
package runtime

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/json"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	cmdFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	grpcRegistry "github.com/oasislabs/ekiden/go/grpc/registry"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

const (
	cfgID                       = "runtime.id"
	cfgTEEHardware              = "runtime.tee_hardware"
	cfgReplicaGroupSize         = "runtime.replica_group_size"
	cfgReplicaGroupBackupSize   = "runtime.replica_group_backup_size"
	cfgReplicaAllowedStragglers = "runtime.replica_allowed_stragglers"
	cfgStorageGroupSize         = "runtime.storage_group_size"
)

var (
	runtimeCmd = &cobra.Command{
		Use:   "runtime",
		Short: "runtime registry backend utilities",
	}

	registerCmd = &cobra.Command{
		Use:   "register",
		Short: "register a runtime",
		PreRun: func(cmd *cobra.Command, args []string) {
			cmdGrpc.RegisterClientFlags(cmd, false)
			registerRegFlags(cmd)
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

func doRegister(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	var id signature.PublicKey
	if err := id.UnmarshalHex(viper.GetString(cfgID)); err != nil {
		logger.Error("failed to parse runtime ID",
			"err", err,
		)
		os.Exit(1)
	}

	var teeHardware node.TEEHardware
	switch strings.ToLower(viper.GetString(cfgTEEHardware)) {
	case "invalid":
	case "intel-sgx":
		teeHardware = node.TEEHardwareIntelSGX
	default:
		logger.Error("invalid TEE hardware")
		os.Exit(1)
	}

	rt := &registry.Runtime{
		ID:                       id,
		Code:                     nil, // TBD
		FeaturesSGX:              teeHardware == node.TEEHardwareIntelSGX,
		ReplicaGroupSize:         uint64(viper.GetInt64(cfgReplicaGroupSize)),
		ReplicaGroupBackupSize:   uint64(viper.GetInt64(cfgReplicaGroupBackupSize)),
		ReplicaAllowedStragglers: uint64(viper.GetInt64(cfgReplicaAllowedStragglers)),
		StorageGroupSize:         uint64(viper.GetInt64(cfgStorageGroupSize)),
	}

	nrRetries := cmdFlags.Retries()
	for i := 0; i < nrRetries; {
		if err := actuallyRegister(cmd, &id, rt); err == nil {
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

func actuallyRegister(cmd *cobra.Command, id *signature.PublicKey, rt *registry.Runtime) error {
	conn, client := doConnect(cmd)
	defer conn.Close()

	rt.RegistrationTime = uint64(time.Now().Unix())

	// Note: This can currently be absolutely anything, the registry just
	// checks that the signature is valid, but doesn't care about the signing
	// key.
	//
	// At some point in the future it probably should be an entity key.
	owner, err := signature.NewPrivateKey(rand.Reader)
	if err != nil {
		logger.Error("failed to generate a temporary signing key",
			"err", err,
		)
		return err
	}

	signed, err := registry.SignRuntime(owner, registry.RegisterRuntimeSignatureContext, rt)
	if err != nil {
		logger.Error("failed to sign runtime descriptor",
			"err", err,
		)
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
		"runtime", id,
	)

	return nil
}

func doList(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, client := doConnect(cmd)
	defer conn.Close()

	runtimes, err := client.GetRuntimes(context.Background(), &grpcRegistry.RuntimesRequest{})
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

func registerRegFlags(cmd *cobra.Command) {
	cmdFlags.RegisterRetries(cmd)

	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgID, "", "Runtime ID")
		cmd.Flags().String(cfgTEEHardware, "invalid", "Type of TEE hardware.  Supported values are \"invalid\" and \"intel-sgx\"")
		cmd.Flags().Uint64(cfgReplicaGroupSize, 1, "Number of workers in the runtime replica group")
		cmd.Flags().Uint64(cfgReplicaGroupBackupSize, 0, "Number of backup workers in the runtime replica group")
		cmd.Flags().Uint64(cfgReplicaAllowedStragglers, 0, "Number of stragglers allowed per round in the runtime replica group")
		cmd.Flags().Uint64(cfgStorageGroupSize, 1, "Number of storage nodes for the runtime")
	}

	for _, v := range []string{
		cfgID,
		cfgTEEHardware,
		cfgReplicaGroupSize,
		cfgReplicaGroupBackupSize,
		cfgReplicaAllowedStragglers,
		cfgStorageGroupSize,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}

// Register registers the runtime sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	for _, v := range []*cobra.Command{
		registerCmd,
		listCmd,
	} {
		runtimeCmd.AddCommand(v)
	}

	cmdGrpc.RegisterClientFlags(listCmd, false)
	cmdFlags.RegisterVerbose(listCmd)

	cmdGrpc.RegisterClientFlags(registerCmd, false)
	registerRegFlags(registerCmd)

	parentCmd.AddCommand(runtimeCmd)
}
