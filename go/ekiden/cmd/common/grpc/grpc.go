// Package grpc implements common gRPC command-line flags.
package grpc

import (
	"crypto/tls"
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
		cmd.Flags().Uint16(cfgGRPCPort, 9001, "gRPC server port")
	}

	for _, v := range []string{
		cfgGRPCPort,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	cmnGrpc.RegisterServerFlags(cmd)
}

// RegisterServerLocalFlags registers the flags used by the gRPC server.
func RegisterServerLocalFlags(cmd *cobra.Command) {
	cmnGrpc.RegisterServerFlags(cmd)

	if !cmd.Flags().Parsed() {
		cmd.Flags().Uint16(cfgDebugPort, 0, "gRPC server debug port (INSECURE/UNSAFE)")
	}

	for _, v := range []string{
		cfgDebugPort,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
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
		flagSet.StringP(cfgAddress, "a", defaultAddress, "remote gRPC address")
	}

	if persistent {
		_ = viper.BindPFlag(cfgAddress, flagSet.Lookup(cfgAddress))
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
