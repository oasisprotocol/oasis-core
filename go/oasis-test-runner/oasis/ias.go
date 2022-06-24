package oasis

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	tlsCert "github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	iasProxyApi "github.com/oasisprotocol/oasis-core/go/ias/proxy"
	iasCmd "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/ias"
)

var mockSPID []byte

type iasProxy struct {
	*Node

	mock     bool
	grpcPort uint16

	tlsPublicKey signature.PublicKey
}

func (ias *iasProxy) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowRoot().
		debugAllowTestKeys().
		debugSetRlimit().
		grpcServerPort(ias.grpcPort).
		grpcWait()

	// If non-mock, IAS Proxy should get the SPID and API key through env vars.
	if ias.mock {
		args.iasDebugMock().iasSPID(mockSPID)
	}

	// XXX: IAS proxy is started before the validators. Pregenerate temp validator internal socket path.
	if ias.net.cfg.UseShortGrpcSocketPaths && ias.net.validators[0].customGrpcSocketPath == "" {
		ias.net.validators[0].customGrpcSocketPath = ias.net.generateTempSocketPath("ias")
	}
	args.internalSocketAddress(ias.net.validators[0].SocketPath())

	return nil
}

func (ias *iasProxy) CustomStart(args *argBuilder) error {
	if err := ias.net.startOasisNode(ias.Node, []string{"ias", "proxy"}, args); err != nil {
		return fmt.Errorf("oasis/ias: failed to launch node %s: %w", ias.Name, err)
	}

	return nil
}

func (net *Network) newIASProxy() (*iasProxy, error) {
	if net.iasProxy != nil {
		return nil, fmt.Errorf("oasis/ias: already provisioned")
	}

	iasName := "ias-proxy"
	host, err := net.GetNamedNode(iasName, nil)
	if err != nil {
		return nil, err
	}

	// Pre-provision the IAS TLS certificates as they are used by other nodes
	// during startup.
	tlsCertPath, tlsKeyPath := iasCmd.TLSCertPaths(host.dir.String())
	iasCert, err := tlsCert.LoadOrGenerate(tlsCertPath, tlsKeyPath, iasProxyApi.CommonName)
	if err != nil {
		net.logger.Error("failed to generate IAS proxy TLS cert",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/ias: failed to generate IAS proxy TLS cert: %w", err)
	}
	tlsPublicKey := iasCert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)

	net.iasProxy = &iasProxy{
		Node:     host,
		mock:     net.cfg.IAS.Mock,
		grpcPort: host.getProvisionedPort("iasgrpc"),
	}

	// Store TLS public key so other nodes can configure authentication.
	if err = net.iasProxy.tlsPublicKey.UnmarshalBinary(tlsPublicKey[:]); err != nil {
		return nil, fmt.Errorf("oasis/ias: failed to unmarshal IAS proxy TLS public key: %w", err)
	}

	host.features = append(host.features, net.iasProxy)

	return net.iasProxy, nil
}

func init() {
	mockSPID, _ = hex.DecodeString("9b3085a55a5863f7cc66b380dcad0082")
}
