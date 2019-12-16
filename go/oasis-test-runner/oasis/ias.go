package oasis

import (
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"

	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	iasProxyApi "github.com/oasislabs/oasis-core/go/ias/proxy"
	iasCmd "github.com/oasislabs/oasis-core/go/oasis-node/cmd/ias"
)

var mockSPID []byte

type iasProxy struct {
	Node

	grpcPort uint16
}

func (ias *iasProxy) tlsCertPath() string {
	tlsCertPath, _ := iasCmd.TLSCertPaths(ias.dir.String())
	return tlsCertPath
}

func (ias *iasProxy) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		grpcServerPort(ias.grpcPort).
		iasUseGenesis().
		iasDebugMock().
		iasSPID(mockSPID)

	var err error
	if ias.cmd, ias.exitCh, err = ias.net.startOasisNode(
		ias.dir,
		[]string{"ias", "proxy"},
		args,
		ias.Name,
		false,
		false,
	); err != nil {
		return fmt.Errorf("oasis/ias: failed to launch node %s: %w", ias.Name, err)
	}

	return nil
}

func (net *Network) newIASProxy() (*iasProxy, error) {
	if net.iasProxy != nil {
		return nil, errors.New("oasis/ias: already provisioned")
	}

	iasName := "ias-proxy"

	iasDir, err := net.baseDir.NewSubDir(iasName)
	if err != nil {
		net.logger.Error("failed to create ias proxy subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/ias: failed to create ias proxy subdir")
	}

	// Pre-provision the IAS TLS certificates as they are used by other nodes
	// during startup.
	tlsCertPath, tlsKeyPath := iasCmd.TLSCertPaths(iasDir.String())
	if _, err = tlsCert.LoadOrGenerate(tlsCertPath, tlsKeyPath, iasProxyApi.CommonName); err != nil {
		net.logger.Error("failed to generate IAS proxy TLS cert",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/ias: failed to generate IAS proxy TLS cert")
	}

	net.iasProxy = &iasProxy{
		Node: Node{
			Name: iasName,
			net:  net,
			dir:  iasDir,
		},
		grpcPort: net.nextNodePort,
	}
	net.iasProxy.doStartNode = net.iasProxy.startNode

	net.nextNodePort++

	return net.iasProxy, nil
}

func init() {
	mockSPID, _ = hex.DecodeString("9b3085a55a5863f7cc66b380dcad0082")
}
