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
	"github.com/oasislabs/ekiden/go/genesis/api"
)

const (
	testServer1Address = "127.0.0.1:36578"
	testServer2Address = "127.0.0.1:36579"
)

func generateValidator(t *testing.T, index int) *api.Validator {
	privKey, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	return &api.Validator{
		PubKey:      privKey.Public(),
		Name:        fmt.Sprintf("validator-%d", index),
		Power:       10,
		CoreAddress: fmt.Sprintf("127.0.0.1:%d", 1000+index),
	}
}

func generateSeed(t *testing.T, index int) *SeedNode {
	privKey, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	return &SeedNode{
		PubKey:      privKey.Public(),
		CoreAddress: fmt.Sprintf("127.0.0.1:%d", 1000+index),
	}
}

func TestBootstrapGenesis(t *testing.T) {
	numValidators := 3
	numSeeds := 0

	tmpDir, err := ioutil.TempDir("", "ekiden-bootstrap-test")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(tmpDir)

	// Create fake genesis document template.
	template := &api.Document{
		ExtraData: map[string][]byte{
			"1": []byte("The state lieth in all languages good and evil;"),
			"2": []byte("and whatever it saith it lieth;"),
			"3": []byte("and whatever it hath it hath stolen."),
		},
	}

	// Create a bootstrap server.
	srv, err := NewServer(testServer1Address, numValidators, numSeeds, template, tmpDir)
	require.NoError(t, err, "NewServer")

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Wait for the server to start.
	time.Sleep(1 * time.Second)

	// Spawn a client first. It should block until all the validators
	// are registered.
	genDocCh := make(chan interface{}, numValidators+1)
	go func() {
		genDoc, gerr := getGenesis(testServer1Address)
		if gerr != nil {
			genDocCh <- gerr
		} else {
			genDocCh <- genDoc
		}
	}()

	// Create some validators.
	var validatorMapKeys []signature.MapKey
	validators := make(map[signature.MapKey]*api.Validator)
	for i := 1; i <= numValidators; i++ {
		v := generateValidator(t, i)
		k := v.PubKey.ToMapKey()
		validators[k] = v
		validatorMapKeys = append(validatorMapKeys, k)

		go func(v *api.Validator) {
			var genDoc *api.Document
			gerr := registerValidator(testServer1Address, v)
			if gerr == nil {
				genDoc, gerr = getGenesis(testServer1Address)
			}
			if gerr != nil {
				genDocCh <- gerr
			} else {
				genDocCh <- genDoc
			}
		}(v)
	}

	// All genesis documents should be equal and valid.
	var genesisTime time.Time
	checkGenesisDoc := func(genDoc *api.Document) {
		if genesisTime.IsZero() {
			genesisTime = genDoc.Time
		} else {
			require.Equal(t, genesisTime, genDoc.Time)
		}

		require.NotNil(t, genDoc, "failed to receive genesis document")
		require.Equal(t, numValidators, len(genDoc.Validators), "incorrect number of validators")
		require.EqualValues(t, template.Registry, genDoc.Registry, "invalid genesis document content (registry)")
		require.EqualValues(t, template.RootHash, genDoc.RootHash, "invalid genesis document content (root hash)")
		require.EqualValues(t, template.Storage, genDoc.Storage, "invalid genesis document content (storage)")
		require.EqualValues(t, template.Staking, genDoc.Staking, "invalid genesis document content (staking)")
		require.EqualValues(t, template.ExtraData, genDoc.ExtraData, "invalid genesis document content (extra data)")

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
			switch r := genDoc.(type) {
			case *api.Document:
				checkGenesisDoc(r)
			case error:
				require.Failf(t, "failed to get genesis document", "error: %s", r.Error())
			default:
				require.Fail(t, "unknown type")
			}
		case <-time.After(1 * time.Second):
			require.Fail(t, "timed out waiting for genesis document")
		}
	}

	// After the genesis document is generated, we should still be
	// able to update validator addresses.
	v := validators[validatorMapKeys[0]]
	v.CoreAddress = "127.1.1.1:1001"
	err = registerValidator(testServer1Address, v)
	var genDoc *api.Document
	if err == nil {
		genDoc, err = getGenesis(testServer1Address)
	}
	require.NoError(t, err, "updating a validator address must not fail")
	checkGenesisDoc(genDoc)

	// But we should not be able to modify validator names.
	mv := *v
	mv.Name = "foovalidator"
	err = registerValidator(testServer1Address, &mv)
	require.Error(t, err, "updating a validator name must fail")

	// But after the genesis document is generated, we should not be
	// able to add new validators.
	newValidator := generateValidator(t, 0)
	err = registerValidator(testServer1Address, newValidator)
	require.Error(t, err, "adding a validator after genesis must fail")

	// Check that we can restore from a generated genesis file. We start
	// a second server in the same data directory.

	// Create a bootstrap server.
	srv, err = NewServer(testServer2Address, numValidators, numSeeds, template, tmpDir)
	require.NoError(t, err, "NewServer")

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Wait for the server to start.
	time.Sleep(1 * time.Second)

	// Genesis file should be immediately available to a client.
	genDocCh = make(chan interface{}, 1)
	go func() {
		genDoc, gerr := getGenesis(testServer2Address) // nolint: govet
		if gerr != nil {
			genDocCh <- gerr
		} else {
			genDocCh <- genDoc
		}
	}()

	select {
	case genDoc := <-genDocCh:
		switch r := genDoc.(type) {
		case *api.Document:
			checkGenesisDoc(r)
		case error:
			require.Failf(t, "failed to get genesis document", "error: %s", r.Error())
		default:
			require.Fail(t, "unknown type")
		}
	case <-time.After(1 * time.Second):
		require.Fail(t, "timed out waiting for genesis document after restore")
	}

	// After the genesis document is generated, we should still be
	// able to update validator addresses.
	v = validators[validatorMapKeys[0]]
	v.CoreAddress = "127.2.2.2:1001"
	err = registerValidator(testServer2Address, v)
	if err == nil {
		genDoc, err = getGenesis(testServer2Address)
	}
	require.NoError(t, err, "updating a validator address must not fail")
	checkGenesisDoc(genDoc)
}

func TestBootstrapSeeds(t *testing.T) {
	numValidators := 0
	numSeeds := 3

	tmpDir, err := ioutil.TempDir("", "ekiden-bootstrap-test")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(tmpDir)

	// Create fake app state.
	template := &api.Document{}

	// Create a bootstrap server.
	srv, err := NewServer(testServer1Address, numValidators, numSeeds, template, tmpDir)
	require.NoError(t, err, "NewServer")

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Wait for the server to start.
	time.Sleep(1 * time.Second)

	// Spawn seeds clients. It should block until all seeds are registered.
	genSeedCh := make(chan interface{}, numSeeds+1)
	for i := 1; i <= numSeeds+1; i++ {
		go func() {
			seeds, serr := getSeeds(testServer1Address)
			if serr != nil {
				genSeedCh <- serr
			} else {
				genSeedCh <- seeds
			}
		}()
	}

	// Create some seeds.
	var seedMapKeys []signature.MapKey
	seeds := make(map[signature.MapKey]*SeedNode)
	for i := 1; i <= numSeeds; i++ {
		s := generateSeed(t, i)
		k := s.PubKey.ToMapKey()
		seeds[k] = s
		seedMapKeys = append(seedMapKeys, k)

		gerr := registerSeed(testServer1Address, s)
		require.NoError(t, gerr, "seed registration failed")
	}

	// All received seeds should be equal and valid.
	checkSeeds := func(rcvSeeds []*SeedNode) {
		require.Equal(t, len(seeds), len(rcvSeeds), "incorrect number of seeds")

		for _, rcvSeed := range rcvSeeds {
			sd := seeds[rcvSeed.PubKey.ToMapKey()]
			require.NotNil(t, sd, "incorrect seed")

			require.True(t, rcvSeed.PubKey.Equal(sd.PubKey), "incorrect received seed public key")
			require.EqualValues(t, rcvSeed.CoreAddress, sd.CoreAddress)
		}
	}

	for i := 0; i < numSeeds+1; i++ {
		select {
		case rcvSeeds := <-genSeedCh:
			switch r := rcvSeeds.(type) {
			case []*SeedNode:
				checkSeeds(r)
			case error:
				require.Failf(t, "failed to get seeds", "error: %s", r.Error())
			default:
				require.Fail(t, "unknown type")
			}
		case <-time.After(1 * time.Second):
			require.Fail(t, "timed out waiting for seed nodes")
		}
	}

	// After enough seeds are present, we should still be
	// able to update seeds.
	sd := seeds[seedMapKeys[0]]
	sd.CoreAddress = "127.1.1.1:1001"
	err = registerSeed(testServer1Address, sd)
	require.NoError(t, err, "updating a seed must not fail")
	rcvSeeds, serr := getSeeds(testServer1Address)
	require.NoError(t, serr, "getting seeds must not fail")
	checkSeeds(rcvSeeds)

	// We should also be able to also adde new seeds.
	newSeed := generateSeed(t, numSeeds+2)
	// Add seed to local map.
	seeds[newSeed.PubKey.ToMapKey()] = newSeed
	// Register seed.
	err = registerSeed(testServer1Address, newSeed)
	require.NoError(t, err, "adding a new seed should not fail")
	rcvSeeds, serr = getSeeds(testServer1Address)
	require.NoError(t, serr, "getting seeds must not fail")
	checkSeeds(rcvSeeds)

	// Check that we can restore from seed file. We start
	// a second server in the same data directory.

	// Create a bootstrap server.
	srv, err = NewServer(testServer2Address, numValidators, numSeeds, template, tmpDir)
	require.NoError(t, err, "NewServer")

	err = srv.Start()
	require.NoError(t, err)
	defer srv.Stop()

	// Wait for the server to start.
	time.Sleep(1 * time.Second)

	// Seeds should be immediately available to a client.
	rcvSeeds, serr = getSeeds(testServer1Address)
	require.NoError(t, serr, "getting seeds must not fail")
	checkSeeds(rcvSeeds)
}
