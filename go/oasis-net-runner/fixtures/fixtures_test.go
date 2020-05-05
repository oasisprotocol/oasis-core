package fixtures

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	defaultFixturePath = "../../../tests/fixture-data/net-runner/default.json"
)

func TestDefaultFixture(t *testing.T) {
	f, err := newDefaultFixture()
	require.Nil(t, err)
	require.NotNil(t, f)

	data, err := DumpFixture(f)
	require.Nil(t, err)
	require.NotNil(t, data)

	// As cool as having tests cases is, having to regenerate test data
	// every single time the default fixture changes is incredibly
	// annoying.
	//
	// May this pearl of wisdom serve as a guiding light for the next
	// unfortunate victim.
	//
	// $ ./oasis-net-runner dump-fixture > /tmp/fuckfuckfuckfuckfuck

	storedData, err := ioutil.ReadFile(defaultFixturePath)
	require.Nil(t, err)
	require.NotNil(t, storedData)

	require.EqualValues(t, storedData, data)
}

func TestCustomFixture(t *testing.T) {
	f, _ := newDefaultFixture()
	f.Network.NodeBinary = "myNodeBinary"
	f.Network.ConsensusBackend = "myConsensusBackend"
	f.Network.ConsensusGasCostsTxByte = 123456789

	data, err := DumpFixture(f)
	require.Nil(t, err)
	tmpFile, _ := ioutil.TempFile("", "oasis-net-runner-customfixture.*.json")
	path := tmpFile.Name()
	_, _ = tmpFile.Write(data)
	tmpFile.Close()

	fs, err := newFixtureFromFile(path)
	require.Nil(t, err)
	require.EqualValues(t, f, fs)
}
