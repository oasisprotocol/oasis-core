package byzantine

import (
	"fmt"
	"net"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
)

type externalGrpc struct {
	grpc *grpc.Server
}

func getGrpcAddress() []node.Address {
	return []node.Address{
		{
			TCPAddr: net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: viper.GetInt(cmdGrpc.CfgServerPort),
			},
		},
	}
}

func newExternalGrpc(id *identity.Identity) (*externalGrpc, error) {
	// Create externally-accessible gRPC server.
	serverConfig := &grpc.ServerConfig{
		Name:     "external",
		Port:     uint16(viper.GetInt(cmdGrpc.CfgServerPort)),
		Identity: id,
	}
	grpc, err := grpc.NewServer(serverConfig)
	if err != nil {
		return nil, err
	}

	g := &externalGrpc{
		grpc,
	}

	return g, nil
}

func (g *externalGrpc) start() error {
	if g.grpc == nil {
		return fmt.Errorf("grpc service not initialized")
	}

	// Run the gRPC server.
	if err := g.grpc.Start(); err != nil {
		return err
	}

	return nil
}

func (g *externalGrpc) stop() {
	if g.grpc == nil {
		return
	}

	g.grpc.Stop()
	g.grpc = nil
}
