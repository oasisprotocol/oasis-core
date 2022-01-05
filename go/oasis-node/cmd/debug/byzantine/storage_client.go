package byzantine

import (
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

var _ storage.Backend = (*storageClient)(nil)

type storageClient struct {
	storage.Backend

	nodeID signature.PublicKey
	initCh chan struct{}
}

func dialOptionForNode(ourCerts []tls.Certificate, node *node.Node) (grpc.DialOption, error) {
	tlsKeys := make(map[signature.PublicKey]bool)
	for _, addr := range node.TLS.Addresses {
		tlsKeys[addr.PubKey] = true
	}

	creds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
		CommonName:    identity.CommonName,
		ServerPubKeys: tlsKeys,
		Certificates:  ourCerts,
	})
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(creds), nil
}

func dialNode(node *node.Node, opts grpc.DialOption) (*grpc.ClientConn, error) {
	manualResolver := manual.NewBuilderWithScheme("oasis-core-resolver")

	conn, err := cmnGrpc.Dial("oasis-core-resolver:///", opts,
		grpc.WithBalancerName(roundrobin.Name), // nolint: staticcheck
		grpc.WithResolvers(manualResolver),
	)
	if err != nil {
		return nil, fmt.Errorf("failed dialing node: %w", err)
	}
	var resolverState resolver.State
	for _, addr := range node.TLS.Addresses {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return conn, nil
}

func newHonestNodeStorage(id *identity.Identity, node *node.Node) (*storageClient, error) {
	opts, err := dialOptionForNode([]tls.Certificate{*id.GetTLSCertificate()}, node)
	if err != nil {
		return nil, fmt.Errorf("storage client DialOptionForNode: %w", err)
	}
	conn, err := dialNode(node, opts)
	if err != nil {
		return nil, fmt.Errorf("storage client DialNode: %w", err)
	}

	initCh := make(chan struct{})
	close(initCh)

	return &storageClient{
		Backend: storage.NewStorageClient(conn),
		nodeID:  node.ID,
		initCh:  initCh,
	}, nil
}

func (sc *storageClient) Initialized() <-chan struct{} {
	return sc.initCh
}

func storageConnectToCommittee(ht *honestTendermint, height int64, committee *scheduler.Committee, role scheduler.Role, id *identity.Identity) ([]*storageClient, error) {
	var clients []*storageClient
	if err := schedulerForRoleInCommittee(ht, height, committee, role, func(n *node.Node) error {
		// Skip any node sthat don't expose public storage RPC.
		if !n.HasRoles(node.RoleStorageRPC) {
			return nil
		}

		client, err := newHonestNodeStorage(id, n)
		if err != nil {
			return fmt.Errorf("new honest node storage %s: %w", n.ID, err)
		}

		clients = append(clients, client)

		return nil
	}); err != nil {
		return nil, err
	}

	return clients, nil
}

func storageBroadcastCleanup(clients []*storageClient) {
	for _, sc := range clients {
		sc.Cleanup()
	}
}
