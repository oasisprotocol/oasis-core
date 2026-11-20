package aesm

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestGetTargetInfoSendsZeroBufferSize(t *testing.T) {
	dir, err := os.MkdirTemp("", "aesm-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "s"))
	require.NoError(t, err)
	defer listener.Close()

	type result struct {
		request *Request
		err     error
	}
	requestResult := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			requestResult <- result{err: err}
			return
		}
		defer conn.Close()

		var length [4]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			requestResult <- result{err: err}
			return
		}
		body := make([]byte, binary.LittleEndian.Uint32(length[:]))
		if _, err = io.ReadFull(conn, body); err != nil {
			requestResult <- result{err: err}
			return
		}
		request := &Request{}
		if err = proto.Unmarshal(body, request); err != nil {
			requestResult <- result{err: err}
			return
		}

		errorCode := uint32(1) // Stop after the size query; the next AESM request is unrelated.
		response, err := proto.Marshal(&Response{
			InitQuoteExRes: &Response_InitQuoteExResponse{ErrorCode: &errorCode},
		})
		if err == nil {
			binary.LittleEndian.PutUint32(length[:], uint32(len(response)))
			_, err = conn.Write(append(length[:], response...))
		}
		requestResult <- result{request: request, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = NewClient(listener.Addr().String()).GetTargetInfo(ctx, &AttestationKeyID{})
	require.Error(t, err)

	select {
	case got := <-requestResult:
		require.NoError(t, got.err)
		require.NotNil(t, got.request.InitQuoteExReq)
		require.NotNil(t, got.request.InitQuoteExReq.BufSize)
		require.Zero(t, *got.request.InitQuoteExReq.BufSize)
	case <-ctx.Done():
		t.Fatal("AESM request timed out")
	}
}
