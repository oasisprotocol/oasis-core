package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHostPort(t *testing.T) {
	// Plain addresses.
	address, _ := GetHostPort("[::]:42")
	require.Equal(t, "[::]:42", address)
	address, _ = GetHostPort("[fe80::1]:42")
	require.Equal(t, "[fe80::1]:42", address)
	address, _ = GetHostPort("127.0.0.1:42")
	require.Equal(t, "127.0.0.1:42", address)
	address, _ = GetHostPort("example.org:42")
	require.Equal(t, "example.org:42", address)

	// URLs with scheme.
	address, _ = GetHostPort("http://[::]")
	require.Equal(t, "[::]:80", address)
	address, _ = GetHostPort("http://127.0.0.1")
	require.Equal(t, "127.0.0.1:80", address)
	address, _ = GetHostPort("http://example.org")
	require.Equal(t, "example.org:80", address)

	address, _ = GetHostPort("https://[::]")
	require.Equal(t, "[::]:443", address)
	address, _ = GetHostPort("https://127.0.0.1")
	require.Equal(t, "127.0.0.1:443", address)
	address, _ = GetHostPort("https://example.org")
	require.Equal(t, "example.org:443", address)

	// Complete URL, shouldn't contain a path.
	_, err := GetHostPort("http://example.org:42/")
	require.Error(t, err)
	_, err = GetHostPort("http://example.org/path")
	require.Error(t, err)

	// Port precedence.
	address, _ = GetHostPort("https://[::]:42")
	require.Equal(t, "[::]:42", address)
	address, _ = GetHostPort("foo://[::]:42")
	require.Equal(t, "[::]:42", address)

	// Incomplete URLs.
	_, err = GetHostPort("127.0.0.1")
	require.Error(t, err)
	_, err = GetHostPort("example.org")
	require.Error(t, err)
	_, err = GetHostPort("foo://127.0.0.1")
	require.Error(t, err)
}

func TestIsAddrPort(t *testing.T) {
	for _, v := range []struct {
		data string
		ok   bool
	}{
		{"foo:123", false},
		{"127.0.0.1", false},
		{"127.0.0.1:123", true},
		{"127.0.0.1:0", false},
		{"127.0.0.1:bah", false},
		{"", false},
		{":123", false},
	} {
		err := IsAddrPort(v.data)
		if v.ok {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}
