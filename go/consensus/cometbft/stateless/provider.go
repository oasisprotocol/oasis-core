package stateless

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// NewProvider creates a new consensus provider for the stateless client.
func NewProvider(address string) (*consensusAPI.Client, error) {
	conn, err := cmnGrpc.Dial(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, err
	}

	return consensusAPI.NewClient(conn), nil
}
