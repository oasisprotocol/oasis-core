package byzantine

import (
	"net"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
)

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
