package byzantine

import (
	"fmt"
	"net"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
)

const (
	defaultRuntimeIDHex = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	defaultRuntimeID signature.PublicKey
	fakeAddresses    = []node.Address{
		node.Address{
			TCPAddr: net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 11004,
			},
		},
	}
)

func initDefaultIdentity(dataDir string) (*identity.Identity, error) {
	signerFactory := fileSigner.NewFactory(dataDir, signature.SignerNode, signature.SignerP2P, signature.SignerEntity)
	id, err := identity.LoadOrGenerate(dataDir, signerFactory)
	if err != nil {
		return nil, errors.Wrap(err, "identity LoadOrGenerate")
	}
	return id, nil
}

func init() {
	if err := defaultRuntimeID.UnmarshalHex(defaultRuntimeIDHex); err != nil {
		panic(fmt.Sprintf("default runtime ID UnmarshalHex: %+v", err))
	}
}
