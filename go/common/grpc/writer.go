package grpc

import (
	"io"

	"google.golang.org/grpc"
)

type streamWriter struct {
	grpc.ServerStream
}

// Implements io.Writer.
func (c *streamWriter) Write(p []byte) (int, error) {
	err := c.SendMsg(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// NewStreamWriter wraps a server-side gRPC stream into an io.Writer interface so that a stream can
// be used as a writer. Each Write into such a strema will cause a message to be sent, encoded as a
// raw byte slice.
func NewStreamWriter(stream grpc.ServerStream) io.Writer {
	return &streamWriter{stream}
}
