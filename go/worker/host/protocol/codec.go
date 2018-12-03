package protocol

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/oasislabs/ekiden/go/common/cbor"
)

// Maximum message size.
const maxMessageSize = 104857600 // 100MB

var errMessageTooLarge = errors.New("codec: message too large")

// MessageReader is a reader wrapper that decodes CBOR-encoded Message structures.
type MessageReader struct {
	reader io.Reader
}

// Read deserializes a single CBOR-encoded Message from the underlying reader.
func (c *MessageReader) Read(msg *Message) error {
	// Read 32-bit length prefix.
	rawLength := make([]byte, 4)
	if _, err := io.ReadAtLeast(c.reader, rawLength, 4); err != nil {
		return err
	}

	length := binary.BigEndian.Uint32(rawLength)
	if length > maxMessageSize {
		return errMessageTooLarge
	}

	// Read message bytes.
	rawMessage := make([]byte, length)
	if _, err := io.ReadFull(c.reader, rawMessage); err != nil {
		return err
	}

	// Decode CBOR into given message.
	if err := cbor.Unmarshal(rawMessage, msg); err != nil {
		return err
	}

	return nil
}

// MessageWriter is a writer wrapper that encodes Messages structures to CBOR.
type MessageWriter struct {
	writer io.Writer
}

// Write serializes a single Message to CBOR and writes it to the underlying writer.
func (c *MessageWriter) Write(msg *Message) error {
	// Encode into CBOR.
	data := cbor.Marshal(msg)
	if len(data) > maxMessageSize {
		return errMessageTooLarge
	}

	// Write 32-bit length prefix and encoded data.
	rawLength := make([]byte, 4)
	binary.BigEndian.PutUint32(rawLength, uint32(len(data)))
	if _, err := c.writer.Write(rawLength); err != nil {
		return err
	}
	if _, err := c.writer.Write(data); err != nil {
		return err
	}

	return nil
}

// MessageCodec is a length-prefixed Message encoder/decoder.
type MessageCodec struct {
	MessageReader
	MessageWriter
}

// NewMessageCodec constructs a new Message encoder/decoder.
func NewMessageCodec(rw io.ReadWriter) *MessageCodec {
	return &MessageCodec{
		MessageReader: MessageReader{reader: rw},
		MessageWriter: MessageWriter{writer: rw},
	}
}
