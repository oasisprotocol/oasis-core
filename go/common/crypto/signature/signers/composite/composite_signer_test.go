package composite

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestCompositeSigner(t *testing.T) {
	require := require.New(t)

	testRoles := []signature.SignerRole{
		signature.SignerEntity,
		signature.SignerP2P,
	}

	cfg := FactoryConfig{
		signature.SignerEntity: memory.NewFactory(),
		signature.SignerP2P:    nil,
	}

	_, err := NewFactory(cfg, testRoles...)
	require.Equal(signature.ErrRoleMismatch, err, "config/role mismatch")

	fileFac, err := file.NewFactory("/whatever", testRoles...)
	require.NoError(err, "new file factory")
	cfg[signature.SignerP2P] = fileFac

	sf, err := NewFactory(cfg, testRoles...)
	require.NoError(err, "new factory")

	for _, v := range signature.SignerRoles {
		err = sf.EnsureRole(v)
		if cfg[v] != nil {
			require.NoError(err, "EnsureRole: configured")
		} else {
			require.Equal(signature.ErrRoleMismatch, err, "EnsureRole: not configured")
		}
	}

	signer, err := sf.Generate(signature.SignerEntity, rand.Reader)
	require.NoError(err, "Generate: memory")
	require.IsType(&memory.Signer{}, signer, "Generate: configured")

	_, err = sf.Generate(signature.SignerConsensus, rand.Reader)
	require.Equal(signature.ErrRoleMismatch, err, "Generate: not configured")

	_, err = sf.Load(signature.SignerEntity)
	require.Equal(signature.ErrNotExist, err, "Load: configured") // memory can't load

	_, err = sf.Load(signature.SignerConsensus)
	require.Equal(signature.ErrRoleMismatch, err, "Load: not configured")
}
