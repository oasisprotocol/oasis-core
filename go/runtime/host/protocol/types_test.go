package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBody_Type(t *testing.T) {
	b := Body{
		Empty: &Empty{},
	}
	require.Equal(t, b.Type(), "Empty")

	b = Body{
		RuntimeCapabilityTEERakInitRequest: &RuntimeCapabilityTEERakInitRequest{TargetInfo: []byte{'a', 'b', 'c', 'd'}},
	}
	require.Equal(t, b.Type(), "RuntimeCapabilityTEERakInitRequest")

	b = Body{
		RuntimeCapabilityTEERakInitRequest: &RuntimeCapabilityTEERakInitRequest{TargetInfo: []byte{'a', 'b', 'c', 'd'}},
		RuntimeRPCCallRequest: &RuntimeRPCCallRequest{
			Request: []byte{'a', 'b', 'c', 'd'},
		},
	}
	// First non-nil member should be considered.
	require.Equal(t, b.Type(), "RuntimeCapabilityTEERakInitRequest")

	b = Body{}
	// All members are nil, expect empty string.
	require.Equal(t, b.Type(), "")
}
