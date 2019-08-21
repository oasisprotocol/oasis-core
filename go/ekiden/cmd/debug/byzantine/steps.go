package byzantine

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/identity"
)

const (
	defaultRuntimeIDHex = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	defaultRuntimeID signature.PublicKey
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
