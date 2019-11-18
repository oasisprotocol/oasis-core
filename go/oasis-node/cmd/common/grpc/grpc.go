// Package grpc implements common gRPC command-line flags.
package grpc

import (
	"crypto/tls"
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
)

const (
	// CfgServerPort configures the server port.
	CfgServerPort = "grpc.port"
	// CfgDebugPort configures the remote address.
	CfgAddress = "address"

	defaultAddress      = "127.0.0.1:42261"
	localSocketFilename = "internal.sock"
)

var (
	// ServerTCPFlags has the flags used by the gRPC server.
	ServerTCPFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ServerLocalFlags has the flags used by the gRPC server.
	ServerLocalFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ClientFlags has the flags for a gRPC client.
	ClientFlags = flag.NewFlagSet("", flag.ContinueOnError)
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
		Certificate:    cert,
		InstallWrapper: installWrapper,
	}
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
	path := filepath.Join(dataDir, localSocketFilename)

	config := &cmnGrpc.ServerConfig{
		Name:           "internal",
		Path:           path,
		InstallWrapper: installWrapper,
	}

	return cmnGrpc.NewServer(config)
}

// NewClient connects to a remote gRPC server.
func NewClient(cmd *cobra.Command) (*grpc.ClientConn, error) {
	addr, _ := cmd.Flags().GetString(CfgAddress)

	conn, err := grpc.Dial(addr, grpc.WithInsecure()) // TODO: TLS?
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func init() {
	ServerTCPFlags.Uint16(CfgServerPort, 9001, "gRPC server port")
	_ = viper.BindPFlags(ServerTCPFlags)
	ServerTCPFlags.AddFlagSet(cmnGrpc.Flags)

	ServerLocalFlags.AddFlagSet(cmnGrpc.Flags)

	ClientFlags.StringP(CfgAddress, "a", defaultAddress, "remote gRPC address")
	_ = viper.BindPFlags(ClientFlags)
}
