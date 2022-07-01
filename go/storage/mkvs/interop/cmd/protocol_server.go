package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	badgerNodedb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/interop/fixtures"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	cfgServerSocket  = "socket"
	cfgServerDataDir = "datadir"

	cfgServerFixture = "fixture"
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
		fmt.Println("no data directory specified")
		return
	}

	// Initialize logging.
	logFile := filepath.Join(dataDir, "protocol_server.log")
	w, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Printf("failed to open log file: %v\n", err)
		return
	}
	logWriter := io.MultiWriter(os.Stdout, w)
	if err = logging.Initialize(logWriter, logging.FmtJSON, logging.LevelWarn, nil); err != nil {
		fmt.Printf("failed to initialize logging: %v\n", err)
		return
	}

	genesisTestHelpers.SetTestChainContext()

	// Initialize a dummy storage backend.
	storageCfg := api.Config{
		Backend:      database.BackendNameBadgerDB,
		DB:           dataDir,
		MaxCacheSize: 16 * 1024 * 1024,
	}

	if fixtureName := viper.GetString(cfgServerFixture); fixtureName != "" {
		ctx := context.Background()
		ndbCfg := storageCfg.ToNodeDB()
		var ndb api.NodeDB
		ndb, err = badgerNodedb.New(ndbCfg)
		if err != nil {
			logger.Error("failed to initialize node db",
				"err", err,
			)
			return
		}
		var fixture fixtures.Fixture
		fixture, err = fixtures.GetFixture(fixtureName)
		if err != nil {
			logger.Error("failed getting fixture",
				"err", err,
				"fixture", fixture.Name(),
			)
			return
		}
		var root *node.Root
		root, err = fixture.Populate(ctx, ndb)
		if err != nil {
			logger.Error("failed to populate fixture",
				"err", err,
				"fixture", fixture.Name(),
			)
			return
		}

		fmt.Printf("Fixture: %s, populated root hash: %s\n", fixtureName, root.Hash)

		ndb.Close()
	}

	backend, err := database.New(&storageCfg)
	if err != nil {
		logger.Error("failed to initialize storage backend",
			"err", err,
		)
		return
	}

	// Initialize the JSON-RPC listener/service.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: viper.GetString(cfgServerSocket)})
	if err != nil {
		logger.Error("failed to listen on socket",
			"err", err,
		)
		return
	}
	rpcSvr := newDbRPCService(ln, backend)
	svcMgr.Register(rpcSvr)

	// Start the JSON-RPC server.
	if err := rpcSvr.Start(); err != nil {
		logger.Error("failed to start JSON-RPC server",
			"err", err,
		)
		return
	}

	logger.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	svcMgr.Wait()
}

// RegisterProtoServer registers the grpc-server sub-command and all of it's children.
func RegisterProtoServer(parentCmd *cobra.Command) {
	protoServerCmd.Flags().AddFlagSet(protoServerFlags)

	parentCmd.AddCommand(protoServerCmd)
}

func init() {
	protoServerFlags.String(cfgServerSocket, "storage.sock", "path to storage protocol server socket")
	protoServerFlags.String(cfgServerDataDir, "", "path to data directory")
	protoServerFlags.String(cfgServerFixture, "", "fixture for initializing initial state")
	_ = viper.BindPFlags(protoServerFlags)
}
