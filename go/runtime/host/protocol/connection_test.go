package protocol

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

// TODO: add tests with incorrect handlers (wrong version, malformed response)

type testHandler struct {
	calls int
}

// Implements Handler.
func (h *testHandler) Handle(ctx context.Context, body *Body) (*Body, error) {
	// We need to handle RuntimeInfoRequest for initialization to complete.
	if body.RuntimeInfoRequest != nil {
		return &Body{
			RuntimeInfoResponse: &RuntimeInfoResponse{
				// Need to use the correct version.
				ProtocolVersion: version.RuntimeHostProtocol,
			},
		}, nil
	}

	h.calls++
	return body, nil
}

func TestClose(t *testing.T) {
	require := require.New(t)
	runtimeID := common.NewTestNamespaceFromSeed([]byte("test conn"), 0)

	logger := logging.GetLogger("test")
	handlerA := &testHandler{}
	protoA, err := NewConnection(logger, runtimeID, handlerA)
	require.NoError(err, "NewConnection")
	require.NotPanics(func() { protoA.Close() })
}

func TestEchoRequestResponse(t *testing.T) {
	require := require.New(t)
	runtimeID := common.NewTestNamespaceFromSeed([]byte("test conn"), 0)

	logger := logging.GetLogger("test")
	connA, connB := net.Pipe()
	handlerA := &testHandler{}
	protoA, err := NewConnection(logger, runtimeID, handlerA)
	require.NoError(err, "A.New()")
	handlerB := &testHandler{}
	protoB, err := NewConnection(logger, runtimeID, handlerB)
	require.NoError(err, "B.New()")

	err = protoA.InitGuest(context.Background(), connA)
	require.NoError(err, "A.InitGuest()")
	_, err = protoB.InitHost(context.Background(), connB, &HostInfo{})
	require.NoError(err, "B.InitHost()")

	require.Panics(func() { _, _ = protoA.InitHost(context.Background(), connA, &HostInfo{}) }, "connection reinit should panic")
	require.Panics(func() { _ = protoA.InitGuest(context.Background(), connA) }, "connection reinit should panic")
	require.Panics(func() { _, _ = protoB.InitHost(context.Background(), connB, &HostInfo{}) }, "connection reinit should panic")
	require.Panics(func() { _ = protoB.InitGuest(context.Background(), connB) }, "connection reinit should panic")

	reqA := Body{Empty: &Empty{}}
	respA, err := protoA.Call(context.Background(), &reqA)
	require.NoError(err, "A.Call()")
	require.EqualValues(&reqA, respA, "A.Call()")
	require.EqualValues(0, handlerA.calls, "Handler A must not be called")
	require.EqualValues(1, handlerB.calls, "Handler B must be called")

	reqB := Body{Empty: &Empty{}}
	respB, err := protoB.Call(context.Background(), &reqB)
	require.NoError(err, "B.Call()")
	require.EqualValues(&reqB, respB, "B.Call()")
	require.EqualValues(1, handlerA.calls, "Handler A must be called")
	require.EqualValues(1, handlerB.calls, "Handler B must not be called")

	protoA.Close()
	_, err = protoA.Call(context.Background(), &reqA)
	require.Error(err, "A.Call() must error when connection is closed")

	protoB.Close()
	_, err = protoB.Call(context.Background(), &reqB)
	require.Error(err, "B.Call() must error when connection is closed")

	require.Panics(func() { _, _ = protoA.InitHost(context.Background(), connA, &HostInfo{}) }, "connection reinit should panic")
	require.Panics(func() { _ = protoA.InitGuest(context.Background(), connA) }, "connection reinit should panic")
	require.Panics(func() { _, _ = protoB.InitHost(context.Background(), connB, &HostInfo{}) }, "connection reinit should panic")
	require.Panics(func() { _ = protoB.InitGuest(context.Background(), connB) }, "connection reinit should panic")

	info, err := protoA.GetInfo(context.Background())
	require.Error(err, "GetInfo should fail for guest connections")
	info, err = protoB.GetInfo(context.Background())
	require.NoError(err, "GetInfo should succeed for host connections")
	require.EqualValues(version.RuntimeHostProtocol, info.ProtocolVersion)
}

func TestBigMessage(t *testing.T) {
	require := require.New(t)
	runtimeID := common.NewTestNamespaceFromSeed([]byte("test conn"), 0)
	logger := logging.GetLogger("test")

	connA, connB := net.Pipe()
	handlerA := &testHandler{}
	protoA, err := NewConnection(logger, runtimeID, handlerA)
	require.NoError(err, "A.New()")
	handlerB := &testHandler{}
	protoB, err := NewConnection(logger, runtimeID, handlerB)
	require.NoError(err, "B.New()")

	err = protoA.InitGuest(context.Background(), connA)
	require.NoError(err, "A.InitGuest()")
	_, err = protoB.InitHost(context.Background(), connB, &HostInfo{})
	require.NoError(err, "B.InitHost()")

	rq := make([]byte, 2000000)
	reqA := Body{RuntimeRPCCallRequest: &RuntimeRPCCallRequest{Request: rq}}
	respA, err := protoA.Call(context.Background(), &reqA)
	require.NoError(err, "A.Call()")
	require.EqualValues(&reqA, respA, "A.Call()")
	require.EqualValues(0, handlerA.calls, "Handler A must not be called")
	require.EqualValues(1, handlerB.calls, "Handler B must be called")
}
