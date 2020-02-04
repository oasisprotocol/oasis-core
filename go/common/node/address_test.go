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
			id:               "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBA=",
			addr:             "127.0.0.1:8000",
			consensusAddrStr: "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBA=@127.0.0.1:8000",
		},
		{
			id:               "D2hqhJcmZnBmhw9TodOdoFPAjmRkpRatANCNHxIDHgA=",
			addr:             "35.100.2.11:8000",
			consensusAddrStr: "D2hqhJcmZnBmhw9TodOdoFPAjmRkpRatANCNHxIDHgA=@35.100.2.11:8000",
		},
	}

	for _, testCase := range testCases {
		// Construct a ConsensusAddress object and check if text marshalling works.
		var consensusAddr ConsensusAddress
		require.NoError(t, consensusAddr.ID.UnmarshalText([]byte(testCase.id)), "error unmarshaling consensus address' id")
		require.NoError(t, consensusAddr.Address.UnmarshalText([]byte(testCase.addr)), "error unmarshaling consensus address' TCP address")
		consensusAddrBytes, err := consensusAddr.MarshalText()
		require.NoError(t, err, "error marshalling consensus address")
		require.Equal(t, testCase.consensusAddrStr, string(consensusAddrBytes), "marshalled consensus address does not match")
		// Unmarshal a text ConsensusAddress object and compare it to the constructed object.
		var consensusAddrUnmarshalled ConsensusAddress
		require.NoError(t, consensusAddrUnmarshalled.UnmarshalText([]byte(testCase.consensusAddrStr)), "error unmarshaling consensus address")
		require.Equal(t, consensusAddr, consensusAddrUnmarshalled)
	}
}

func TestCommitteeAddress(t *testing.T) {
	type testCase struct {
		committeeAddress string
	}

	testCases := []testCase{
		{
			committeeAddress: "MIIBSjCB8KADAgECAgEBMAoGCCqGSM49BAMCMBUxEzARBgNVBAMTCm9hc2lzLW5vZGUwHhcNMjAwMTE0MTQyMzU5WhcNMjEwMTE0MTUyMzU5WjAVMRMwEQYDVQQDEwpvYXNpcy1ub2RlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAml6sfT1v+1fnwADmKLT0fsXkhJE1bQDol/utnC2SOApROfdK53koFdNjV+e7i6TMH7JijFls6GmkTd6nIC+jaMxMC8wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAKBggqhkjOPQQDAgNJADBGAiEAhh8Y41Ahhe6YfX9gJlcKEfaZF1pSoErmnuu3//7twtUCIQC9fUavln6Inj/zEK2jYp9WNzaA6SqGkj01mhKJxlINPQ==@127.0.0.1:8000",
		},
	}

	for _, testCase := range testCases {
		// Construct a CommitteeAddress object and check if text marshalling works.
		var committeeAddress CommitteeAddress
		require.NoError(t, committeeAddress.UnmarshalText([]byte(testCase.committeeAddress)), "error unmarshaling committee address")
		committeeAddrBytes, err := committeeAddress.MarshalText()
		require.NoError(t, err, "error marshalling commmittee address")
		require.Equal(t, testCase.committeeAddress, string(committeeAddrBytes), "marshalled committee address does not match")
	}
}
