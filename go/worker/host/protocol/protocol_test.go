package protocol

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/logging"
)

type testHandler struct {
	calls int
}

func (h *testHandler) Handle(ctx context.Context, body *Body) (*Body, error) {
	h.calls++
	return body, nil
}

func TestEchoRequestResponse(t *testing.T) {
	logger := logging.GetLogger("test")
	connA, connB := net.Pipe()
	handlerA := &testHandler{}
	protoA, err := New(logger, connA, handlerA)
	require.NoError(t, err, "A.New()")
	handlerB := &testHandler{}
	protoB, err := New(logger, connB, handlerB)
	require.NoError(t, err, "B.New()")

	reqA := Body{Empty: &Empty{}}
	chA, err := protoA.MakeRequest(context.Background(), &reqA)
	require.NoError(t, err, "A.MakeRequest()")
	respA := <-chA
	require.EqualValues(t, &reqA, respA, "A.MakeRequest()")
	require.EqualValues(t, 0, handlerA.calls, "Handler A must not be called")
	require.EqualValues(t, 1, handlerB.calls, "Handler B must be called")

	reqB := Body{Empty: &Empty{}}
	chB, err := protoB.MakeRequest(context.Background(), &reqB)
	require.NoError(t, err, "B.MakeRequest()")
	respB := <-chB
	require.EqualValues(t, &reqB, respB, "B.MakeRequest()")
	require.EqualValues(t, 1, handlerA.calls, "Handler A must be called")
	require.EqualValues(t, 1, handlerB.calls, "Handler B must not be called")

	protoA.Close()
	_, err = protoA.MakeRequest(context.Background(), &reqA)
	require.Error(t, err, "A.MakeRequest() must error when connection is closed")

	protoB.Close()
	_, err = protoB.MakeRequest(context.Background(), &reqB)
	require.Error(t, err, "B.MakeRequest() must error when connection is closed")
}

func TestBigMessage(t *testing.T) {
	logger := logging.GetLogger("test")
	connA, connB := net.Pipe()
	handlerA := &testHandler{}
	protoA, err := New(logger, connA, handlerA)
	require.NoError(t, err, "A.New()")
	handlerB := &testHandler{}
	_, err = New(logger, connB, handlerB)
	require.NoError(t, err, "B.New()")

	rq := make([]byte, 2000000)
	reqA := Body{WorkerRPCCallRequest: &WorkerRPCCallRequest{Request: rq}}
	chA, err := protoA.MakeRequest(context.Background(), &reqA)
	require.NoError(t, err, "A.MakeRequest()")
	respA := <-chA
	require.EqualValues(t, &reqA, respA, "A.MakeRequest()")
	require.EqualValues(t, 0, handlerA.calls, "Handler A must not be called")
	require.EqualValues(t, 1, handlerB.calls, "Handler B must be called")
}
