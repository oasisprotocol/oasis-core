package p2p

import (
	"time"

	libp2pNet "github.com/libp2p/go-libp2p-net"

	"github.com/oasislabs/ekiden/go/common/cbor"
)

// Stream is a CBOR message stream wrapper.
type Stream struct {
	libp2pNet.Stream

	codec *cbor.MessageCodec

	readTimeout  time.Duration
	writeTimeout time.Duration
}

// Read reads a CBOR message from the stream.
func (s *Stream) Read(msg interface{}) error {
	if err := s.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		return err
	}

	return s.codec.Read(msg)
}

// Write writes a CBOR-serializable message to the stream.
func (s *Stream) Write(msg interface{}) error {
	if err := s.SetWriteDeadline(time.Now().Add(s.readTimeout)); err != nil {
		return err
	}

	return s.codec.Write(msg)
}

// NewStream creates a new stream.
func NewStream(stream libp2pNet.Stream) *Stream {
	return &Stream{
		Stream:       stream,
		codec:        cbor.NewMessageCodec(stream),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
	}
}
