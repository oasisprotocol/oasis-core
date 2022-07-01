// Package grpc implements common gRPC command-line flags.
package grpc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	// CfgServerPort configures the server port.
	CfgServerPort = "grpc.port"
	// CfgAddress configures the remote address.
	CfgAddress = "address"
	// CfgWait waits for the remote address to become available.
	CfgWait = "wait"
	// CfgDebugGrpcInternalSocketPath sets custom internal socket path.
	CfgDebugGrpcInternalSocketPath = "debug.grpc.internal.socket_path"

	// LocalSocketFilename is the filename of the unix socket in node datadir.
	LocalSocketFilename = "internal.sock"

	defaultAddress = "unix:" + LocalSocketFilename
)

var (
	// ServerTCPFlags has the flags used by the gRPC server.
	ServerTCPFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ServerLocalFlags has the flags used by the gRPC server.
	ServerLocalFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ClientFlags has the flags for a gRPC client.
	ClientFlags = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/grpc")
)

// NewServerTCP constructs a new gRPC server service listening on
// a specific TCP port using default arguments.
//
// This internally takes a snapshot of the current global tracer, so
// make sure you initialize the global tracer before calling this.
func NewServerTCP(cert *tls.Certificate, installWrapper bool) (*cmnGrpc.Server, error) {
	config := &cmnGrpc.ServerConfig{
		Name:           "internal",
		Port:           uint16(viper.GetInt(CfgServerPort)),
		Identity:       &identity.Identity{},
		InstallWrapper: installWrapper,
	}
	config.Identity.SetTLSCertificate(cert)
	return cmnGrpc.NewServer(config)
}

// NewServerLocal constructs a new gRPC server service listening on
// a specific AF_LOCAL socket using default arguments.
//
// This internally takes a snapshot of the current global tracer, so
// make sure you initialize the global tracer before calling this.
func NewServerLocal(installWrapper bool) (*cmnGrpc.Server, error) {
	dataDir := common.DataDir()
	if dataDir == "" {
		return nil, errors.New("data directory must be set")
	}
	path := filepath.Join(dataDir, LocalSocketFilename)
	if viper.IsSet(CfgDebugGrpcInternalSocketPath) && flags.DebugDontBlameOasis() {
		logger.Info("overriding internal socket path", "path", viper.GetString(CfgDebugGrpcInternalSocketPath))
		path = viper.GetString(CfgDebugGrpcInternalSocketPath)
	}

	config := &cmnGrpc.ServerConfig{
		Name:           "internal",
		Path:           path,
		InstallWrapper: installWrapper,
	}

	return cmnGrpc.NewServer(config)
}

func NewClient(cmd *cobra.Command) (*grpc.ClientConn, error) {
	addr, _ := cmd.Flags().GetString(CfgAddress)

	if _, err := os.Stat(addr); err == nil {
		logger.Warn(fmt.Sprintf("'%s' is a file name. Assuming 'unix:%s'.", addr, addr))
		addr = "unix:" + addr
	}

	var creds credentials.TransportCredentials
	if strings.HasPrefix(addr, "unix:") {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{})
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if viper.GetBool(CfgWait) {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.WaitForReady(true)))
	}

	conn, err := cmnGrpc.Dial(
		addr,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func init() {
	ServerTCPFlags.Uint16(CfgServerPort, 9001, "gRPC server port")
	_ = viper.BindPFlags(ServerTCPFlags)
	ServerTCPFlags.AddFlagSet(cmnGrpc.Flags)

	ServerLocalFlags.String(CfgDebugGrpcInternalSocketPath, "", "use custom internal unix socket path")
	_ = ServerLocalFlags.MarkHidden(CfgDebugGrpcInternalSocketPath)
	_ = viper.BindPFlags(ServerLocalFlags)
	ServerLocalFlags.AddFlagSet(cmnGrpc.Flags)

	ClientFlags.StringP(CfgAddress, "a", defaultAddress, "remote gRPC address")
	ClientFlags.Bool(CfgWait, false, "wait for gRPC address to become available")
	ClientFlags.AddFlagSet(cmnGrpc.Flags)
	_ = viper.BindPFlags(ClientFlags)
}
