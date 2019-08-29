// Package grpc implements common gRPC command-line flags.
package grpc

import (
	"crypto/tls"
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	ServerTCPFlags   = flag.NewFlagSet("", flag.ContinueOnError)
	ServerLocalFlags = flag.NewFlagSet("", flag.ContinueOnError)
	ClientFlags      = flag.NewFlagSet("", flag.ContinueOnError)
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

// RegisterServerTCPFlags registers the flags used by the gRPC server.
func RegisterServerTCPFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(ServerTCPFlags)
	}

	cmnGrpc.RegisterServerFlags(cmd)
}

// RegisterServerLocalFlags registers the flags used by the gRPC server.
func RegisterServerLocalFlags(cmd *cobra.Command) {
	cmnGrpc.RegisterServerFlags(cmd)

	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(ServerLocalFlags)
	}
}

// RegisterClientFlags registers the flags for a gRPC client.
func RegisterClientFlags(cmd *cobra.Command, persistent bool) {
	var flagSet *pflag.FlagSet
	switch persistent {
	case true:
		flagSet = cmd.PersistentFlags()
	case false:
		flagSet = cmd.Flags()
	}

	if !cmd.Flags().Parsed() {
		flagSet.AddFlagSet(ClientFlags)
	}
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

	ServerLocalFlags.Uint16(cfgDebugPort, 0, "gRPC server debug port (INSECURE/UNSAFE)")

	ClientFlags.StringP(cfgAddress, "a", defaultAddress, "remote gRPC address")

	for _, v := range []*flag.FlagSet{
		ServerTCPFlags,
		ServerLocalFlags,
		ClientFlags,
	} {
		_ = viper.BindPFlags(v)
	}
}
