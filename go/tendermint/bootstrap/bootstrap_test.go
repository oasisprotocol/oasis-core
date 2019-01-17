package bootstrap

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

const (
	testServer1Address = "127.0.0.1:36578"
	testServer2Address = "127.0.0.1:36579"
)

func generateValidator(t *testing.T, index int) *GenesisValidator {
	privKey, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	return &GenesisValidator{
		PubKey:      privKey.Public(),
		Name:        fmt.Sprintf("validator-%d", index),
		Power:       10,
		CoreAddress: fmt.Sprintf("127.0.0.1:%d", 1000+index),
	}
}

func TestBootstrap(t *testing.T) {
	numValidators := 3

	tmpDir, err := ioutil.TempDir("", "ekiden-bootstrap-test")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(tmpDir)

	// Create a bootstrap server.
	srv, err := NewServer(testServer1Address, numValidators, tmpDir)
	require.NoError(t, err, "NewServer")

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Spawn a client first. It should block until all the validators
	// are registered.
	genDocCh := make(chan *GenesisDocument, numValidators+1)
	go func() {
		genDoc, _ := Client(testServer1Address)
		genDocCh <- genDoc
	}()

	// Create some validators.
	var validatorMapKeys []signature.MapKey
	validators := make(map[signature.MapKey]*GenesisValidator)
	for i := 1; i <= numValidators; i++ {
		v := generateValidator(t, i)
		k := v.PubKey.ToMapKey()
		validators[k] = v
		validatorMapKeys = append(validatorMapKeys, k)

		go func(v *GenesisValidator) {
			genDoc, _ := Validator(testServer1Address, v)
			genDocCh <- genDoc
		}(v)
	}

	// All genesis documents should be equal and valid.
	checkGenesisDoc := func(genDoc *GenesisDocument) {
		require.NotNil(t, genDoc, "failed to receive genesis document")
		require.Equal(t, numValidators, len(genDoc.Validators), "incorrect number of validators")

		for _, v := range genDoc.Validators {
			vd := validators[v.PubKey.ToMapKey()]
			require.NotNil(t, vd, "incorrect validator")

			require.True(t, v.PubKey.Equal(vd.PubKey), "incorrect validator public key")
			require.EqualValues(t, v.Name, vd.Name)
			require.EqualValues(t, v.Power, vd.Power)
			require.EqualValues(t, v.CoreAddress, vd.CoreAddress)
		}
	}

	for i := 0; i < numValidators+1; i++ {
		select {
		case genDoc := <-genDocCh:
			checkGenesisDoc(genDoc)
		case <-time.After(1 * time.Second):
			require.Fail(t, "timed out waiting for genesis document")
		}
	}

	// After the genesis document is generated, we should still be
	// able to update validator addresses.
	v := validators[validatorMapKeys[0]]
	v.CoreAddress = "127.1.1.1:1001"
	genDoc, err := Validator(testServer1Address, v)
	require.NoError(t, err, "updating a validator address must not fail")
	checkGenesisDoc(genDoc)

	// But we should not be able to modify validator names.
	mv := *v
	mv.Name = "foovalidator"
	_, err = Validator(testServer1Address, &mv)
	require.Error(t, err, "updating a validator name must fail")

	// But after the genesis document is generated, we should not be
	// able to add new validators.
	newValidator := generateValidator(t, 0)
	_, err = Validator(testServer1Address, newValidator)
	require.Error(t, err, "adding a validator after genesis must fail")

	// Check that we can restore from a generated genesis file. We start
	// a second server in the same data directory.

	// Create a bootstrap server.
	srv, err = NewServer(testServer2Address, numValidators, tmpDir)
	require.NoError(t, err, "NewServer")

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Genesis file should be immediately available to a client.
	genDocCh = make(chan *GenesisDocument, 1)
	go func() {
		genDoc, _ := Client(testServer2Address)
		genDocCh <- genDoc
	}()

	select {
	case genDoc := <-genDocCh:
		checkGenesisDoc(genDoc)
	case <-time.After(1 * time.Second):
		require.Fail(t, "timed out waiting for genesis document after restore")
	}
}
