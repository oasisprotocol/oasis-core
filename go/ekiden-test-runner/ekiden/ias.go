package ekiden

import (
	"encoding/hex"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

var mockSPID []byte

type iasProxy struct {
	net *Network
	dir *env.Dir

	grpcPort uint16
}

func (ias *iasProxy) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		grpcServerPort(ias.grpcPort).
		iasUseGenesis().
		iasDebugMock().
		iasSPID(mockSPID)

	if err := ias.net.startEkidenNode(ias.dir, []string{"ias", "proxy"}, args, "ias-proxy"); err != nil {
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

	net.iasProxy = &iasProxy{
		net:      net,
		dir:      iasDir,
		grpcPort: 9001, // XXX: Make this configurable.
	}

	return net.iasProxy, nil
}

func init() {
	mockSPID, _ = hex.DecodeString("9b3085a55a5863f7cc66b380dcad0082")
}
