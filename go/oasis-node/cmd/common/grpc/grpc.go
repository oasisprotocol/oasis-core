// Package grpc implements common gRPC command-line flags.
package grpc

import (
	"crypto/tls"
	"fmt"
	"os"

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
)

const (
	// CfgServerPort configures the server port.
	CfgServerPort = "grpc.port"
	// CfgAddress configures the remote address.
	CfgAddress = "address"
	// CfgWait waits for the remote address to become available.
	CfgWait = "wait"
	// CfgInsecureLoopback allows non-TLS connection to loopback addresses.
	CfgInsecureLoopback = "insecure"

	defaultAddress = "unix:" + common.InternalSocketName
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
		Identity:       identity.WithTLSCertificate(cert),
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
	config := &cmnGrpc.ServerConfig{
		Name:           "internal",
		Path:           common.InternalSocketPath(),
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
	switch {
	case cmnGrpc.IsSocketAddress(addr):
		creds = insecure.NewCredentials()
	case viper.GetBool(CfgInsecureLoopback) && cmnGrpc.IsLocalAddress(addr):
		creds = insecure.NewCredentials()
	case viper.GetBool(CfgInsecureLoopback):
		return nil, fmt.Errorf("insecure loopback requested but address is not loopback: %s", addr)
	default:
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

	_ = viper.BindPFlags(ServerLocalFlags)
	ServerLocalFlags.AddFlagSet(cmnGrpc.Flags)

	ClientFlags.StringP(CfgAddress, "a", defaultAddress, "remote gRPC address")
	ClientFlags.Bool(CfgWait, false, "wait for gRPC address to become available")
	ClientFlags.BoolP(CfgInsecureLoopback, "k", false, "allows non-TLS connection to loopback addresses")
	ClientFlags.AddFlagSet(cmnGrpc.Flags)
	_ = viper.BindPFlags(ClientFlags)
}
