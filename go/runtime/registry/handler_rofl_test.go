package registry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	rofl "github.com/oasisprotocol/oasis-core/go/runtime/rofl/api"
)

type capturingRuntime struct {
	host.Runtime

	request *protocol.Body
}

func (rt *capturingRuntime) Call(_ context.Context, request *protocol.Body) (*protocol.Body, error) {
	rt.request = request
	return &protocol.Body{
		RuntimeRPCCallResponse: &protocol.RuntimeRPCCallResponse{},
	}, nil
}

func TestROFLHostHandlerEnclaveRPCPeerID(t *testing.T) {
	ronl := &capturingRuntime{}
	rh := &roflHostHandler{
		id: component.ID{Kind: component.ROFL, Name: "example"},
		comps: map[component.ID]host.Runtime{
			component.ID_RONL: ronl,
		},
	}

	_, err := rh.handleHostRPCCall(context.Background(), &protocol.Body{
		HostRPCCallRequest: &protocol.HostRPCCallRequest{
			Endpoint: rofl.EnclaveRPCEndpointRONL,
			Kind:     enclaverpc.KindNoiseSession,
		},
	})
	require.NoError(t, err)
	require.Equal(t, []byte("local:rofl.example"), ronl.request.RuntimeRPCCallRequest.PeerID)
}
