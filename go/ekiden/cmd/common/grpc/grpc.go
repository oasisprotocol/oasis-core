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

	cmnGrpc "github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common"
)

const (
	cfgGRPCPort  = "grpc.port"
	cfgDebugPort = "grpc.debug.port"
	cfgAddress   = "address"

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
func NewServerTCP(cert *tls.Certificate) (*cmnGrpc.Server, error) {
	port := uint16(viper.GetInt(cfgGRPCPort))
	return cmnGrpc.NewServerTCP("internal", port, cert, nil)
}

// NewServerLocal constructs a new gRPC server service listening on
// a specific AF_LOCAL socket using default arguments.
//
// This internally takes a snapshot of the current global tracer, so
// make sure you initialize the global tracer before calling this.
func NewServerLocal() (*cmnGrpc.Server, error) {
	dataDir := common.DataDir()
	if dataDir == "" {
		return nil, errors.New("data directory must be set")
	}

	debugPort := uint16(viper.GetInt(cfgDebugPort))

	path := filepath.Join(dataDir, localSocketFilename)
	return cmnGrpc.NewServerLocal("internal", path, debugPort, nil)
}

// NewClient connects to a remote gRPC server.
func NewClient(cmd *cobra.Command) (*grpc.ClientConn, error) {
	addr, _ := cmd.Flags().GetString(cfgAddress)

	conn, err := grpc.Dial(addr, grpc.WithInsecure()) // TODO: TLS?
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func init() {
	ServerTCPFlags.Uint16(cfgGRPCPort, 9001, "gRPC server port")
	_ = viper.BindPFlags(ServerTCPFlags)
	ServerTCPFlags.AddFlagSet(cmnGrpc.Flags)

	ServerLocalFlags.Uint16(cfgDebugPort, 0, "gRPC server debug port (INSECURE/UNSAFE)")
	_ = viper.BindPFlags(ServerLocalFlags)
	ServerLocalFlags.AddFlagSet(cmnGrpc.Flags)

	ClientFlags.StringP(cfgAddress, "a", defaultAddress, "remote gRPC address")
	_ = viper.BindPFlags(ClientFlags)
}
