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
