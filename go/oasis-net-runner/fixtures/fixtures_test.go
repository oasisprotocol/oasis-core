package fixtures

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
)

func TestDefaultFixture(t *testing.T) {
	f, err := newDefaultFixture()
	require.Nil(t, err)
	require.NotNil(t, f)

	data, err := DumpFixture(f)
	require.Nil(t, err)
	require.NotNil(t, data)
}

func TestCustomFixture(t *testing.T) {
	f, _ := newDefaultFixture()
	f.Network.NodeBinary = "myNodeBinary"
	f.Network.Consensus.Backend = "myConsensusBackend"
	f.Network.Consensus.Parameters.GasCosts = transaction.Costs{
		consensusGenesis.GasOpTxByte: 123456789,
	}

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
