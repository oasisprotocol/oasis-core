package p2p

import (
	"time"

	"github.com/libp2p/go-libp2p-core"

	"github.com/oasislabs/oasis-core/go/common/cbor"
)

// Stream is a CBOR message stream wrapper.
type Stream struct {
	core.Stream

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
func NewStream(stream core.Stream) *Stream {
	return &Stream{
		Stream:       stream,
		codec:        cbor.NewMessageCodec(stream),
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
	}
}
