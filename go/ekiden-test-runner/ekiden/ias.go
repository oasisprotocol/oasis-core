package ekiden

import (
	"encoding/hex"

	"github.com/pkg/errors"

	tlsCert "github.com/oasislabs/ekiden/go/common/crypto/tls"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	iasCmd "github.com/oasislabs/ekiden/go/ekiden/cmd/ias"
)

var mockSPID []byte

type iasProxy struct {
	net *Network
	dir *env.Dir

	grpcPort uint16
}

func (ias *iasProxy) tlsCertPath() string {
	tlsCertPath, _ := iasCmd.TLSCertPaths(ias.dir.String())
	return tlsCertPath
}

func (ias *iasProxy) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		grpcServerPort(ias.grpcPort).
		iasUseGenesis().
		iasDebugMock().
		iasSPID(mockSPID)

	if _, err := ias.net.startEkidenNode(ias.dir, []string{"ias", "proxy"}, args, "ias-proxy", false, false); err != nil {
		return errors.Wrap(err, "ekiden/ias: failed to launch node")
	}

	return nil
}

func (net *Network) newIASProxy() (*iasProxy, error) {
	if net.iasProxy != nil {
		return nil, errors.New("ekiden/ias: already provisioned")
	}

	iasDir, err := net.baseDir.NewSubDir("ias")
	if err != nil {
		net.logger.Error("failed to create ias proxy subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "ekiden/ias: failed to create ias proxy subdir")
	}

	// Pre-provision the IAS TLS certificates as they are used by other nodes
	// during startup.
	tlsCertPath, tlsKeyPath := iasCmd.TLSCertPaths(iasDir.String())
	if _, err = tlsCert.LoadOrGenerate(tlsCertPath, tlsKeyPath, ias.CommonName); err != nil {
		net.logger.Error("failed to generate IAS proxy TLS cert",
			"err", err,
		)
		return nil, errors.Wrap(err, "ekiden/ias: failed to generate IAS proxy TLS cert")
	}

	net.iasProxy = &iasProxy{
		net:      net,
		dir:      iasDir,
		grpcPort: net.nextNodePort,
	}

	net.nextNodePort++

	return net.iasProxy, nil
}

func init() {
	mockSPID, _ = hex.DecodeString("9b3085a55a5863f7cc66b380dcad0082")
}
