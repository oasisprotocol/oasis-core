package node

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsRoutable(t *testing.T) {
	type testCase struct {
		ip         string
		isRoutable bool
	}

	testCases := []testCase{
		// IPv4 routable.
		{"35.237.83.124", true},
		// IPv4 unroutable.
		{"10.10.0.11", false},
		// IPv6 routable.
		{"2001:05c0:9168:0000:0000:0000:0000:0001", true},
		// IPv6 loopback - unroutable.
		{"::1", false},
		// IPv6 - IPv4 mapped - routable.
		{"0000:0000:0000:0000:0000:ffff:35.237.83.124", true},
		// IPv6 - IPv4 mapped - unroutable.
		{"0000:0000:0000:0000:0000:ffff:10.10.0.11", false},
	}

	for _, testCase := range testCases {
		var address Address
		require.NoError(t, address.FromIP(net.ParseIP(testCase.ip), uint16(8000)), "could not parse address")
		require.Equal(t, testCase.isRoutable, address.IsRoutable(), "Unexpected Address IsRoutable().")
	}
}

func TestConsensusAddress(t *testing.T) {
	type testCase struct {
		id               string
		addr             string
		consensusAddrStr string
	}

	testCases := []testCase{
		{
			id:               "deadbeefdeadbeefdeadbeeddeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			addr:             "127.0.0.1:8000",
			consensusAddrStr: "deadbeefdeadbeefdeadbeeddeadbeefdeadbeefdeadbeefdeadbeefdeadbeef@127.0.0.1:8000",
		},
		{
			id:               "bd51dedea0e92070d90386a85a802df6b9bc69e46f10a130caf72e3a1cd64af6",
			addr:             "35.100.2.11:8000",
			consensusAddrStr: "bd51dedea0e92070d90386a85a802df6b9bc69e46f10a130caf72e3a1cd64af6@35.100.2.11:8000",
		},
	}

	for _, testCase := range testCases {
		// Construct a ConsensusAddress object and check if text marshalling works.
		var consensusAddr ConsensusAddress
		require.NoError(t, consensusAddr.ID.UnmarshalHex(testCase.id), "error unmarshalling consensus address' id")
		require.NoError(t, consensusAddr.Address.UnmarshalText([]byte(testCase.addr)), "error unmarshalling consensus address' TCP address")
		consensusAddrBytes, err := consensusAddr.MarshalText()
		require.NoError(t, err, "error marshalling consensus address")
		require.Equal(t, testCase.consensusAddrStr, string(consensusAddrBytes), "marshalled consensus address does not match")
		// Unmarshal a text ConsensusAddress object and compare it to the constructed object.
		var consensusAddrUnmarshalled ConsensusAddress
		require.NoError(t, consensusAddrUnmarshalled.UnmarshalText([]byte(testCase.consensusAddrStr)), "error unmarshalling consensus address")
		require.Equal(t, consensusAddr, consensusAddrUnmarshalled)
	}
}
