package grpc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsLocalRPC(t *testing.T) {
	for _, tc := range []struct {
		name     string
		addr     string
		expected bool
	}{
		// Invalid inputs.
		{"Empty", "", false},
		{"Invalid scheme", "test:localhost:8080", false},

		// Local unix sockets/vsock.
		{"Local unix socket", "unix:///tmp/socket", true},
		{"Local unix socket (abstract)", "unix-abstract:abstract_path", true},
		{"Local vsock", "vsock:2:12345", true},

		// Loopback addresses.
		{"Local IPv4 loopback", "127.0.0.1:8080", true},
		{"Local IPv4 loopback no port", "127.0.0.1", true},
		{"Local IPv6 loopback", "[::1]:8080", true},
		{"Local IPv6 loopback no port", "[::1]", true},
		{"Localhost no port", "localhost", true},
		{"Localhost", "localhost:8080", true},
		{"Localhost explicit scheme", "dns:localhost:8080", true},

		// Non-local addresses.
		{"Non-local address", "example.com", false},
		{"Non-local address with port", "example.com:8080", false},
		{"Non-local with explicit scheme", "dns:example.com", false},
		{"Non-local with authority", "dns://authority/example.com:8080", false},

		// Complex addresses (conservatively considered non-local).
		{"Localhost with authority", "dns://authority/localhost:8080", false},
		{"Localhost non-standard scheme", "test:localhost:8080", false},
	} {
		require.Equal(t, tc.expected, IsLocalAddress(tc.addr), tc.name+": "+tc.addr)
	}
}
