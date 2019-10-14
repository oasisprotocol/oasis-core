package cmd

import (
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasislabs/oasis-core/go/storage"
	storageApi "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

const (
	cfgServerSocket  = "socket"
	cfgServerDataDir = "datadir"
)

var (
	protoServerFlags = flag.NewFlagSet("", flag.ContinueOnError)

	protoServerCmd = &cobra.Command{
		Use:   "proto-server",
		Short: "run simple gRPC server implementing the storage service",
		Run:   doProtoServer,
	}

	logger = logging.GetLogger("cmd/protocol_server")
)

func doProtoServer(cmd *cobra.Command, args []string) {
	svcMgr := background.NewServiceManager(logger)
	defer svcMgr.Cleanup()

	dataDir := viper.GetString(cfgServerDataDir)
	if dataDir == "" {
		logger.Error("no data directory specified")
		return
	}

	// Generate dummy identity.
	ident, err := identity.LoadOrGenerate(dataDir, memorySigner.NewFactory())
	if err != nil {
		logger.Error("failed to generate identity",
			"err", err,
		)
		return
	}

	// Initialize the gRPC server.
	config := &grpc.ServerConfig{
		Name:           "protocol_server",
		Path:           viper.GetString(cfgServerSocket),
		InstallWrapper: false,
	}

	grpcSrv, err := grpc.NewServer(config)
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	svcMgr.Register(grpcSrv)

	// Initialize a dummy storage backend.
	storageCfg := storageApi.Config{
		Backend:            database.BackendNameLevelDB,
		DB:                 dataDir,
		Signer:             ident.NodeSigner,
		ApplyLockLRUSlots:  1,
		InsecureSkipChecks: false,
	}
	backend, err := database.New(&storageCfg)
	if err != nil {
		logger.Error("failed to initialize storage backend",
			"err", err,
		)
		return
	}
	storage.NewGRPCServer(grpcSrv.Server(), backend, &grpc.AllowAllRuntimePolicyChecker{}, false)

	// Start the gRPC server.
	if err := grpcSrv.Start(); err != nil {
		logger.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	logger.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	svcMgr.Wait()
}

// Register registers the grpc-server sub-command and all of it's children.
func RegisterProtoServer(parentCmd *cobra.Command) {
	protoServerCmd.Flags().AddFlagSet(protoServerFlags)

	parentCmd.AddCommand(protoServerCmd)
}

func init() {
	protoServerFlags.String(cfgServerSocket, "storage.sock", "path to storage protocol server socket")
	protoServerFlags.String(cfgServerDataDir, "", "path to data directory")
	_ = viper.BindPFlags(protoServerFlags)
}
