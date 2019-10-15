package cbor

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Maximum message size.
const maxMessageSize = 104857600 // 100MB

var (
	errMessageTooLarge = errors.New("codec: message too large")

	codecValueSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_codec_size",
			Help: "CBOR codec message size",
		},
		[]string{"call"},
	)

	codecCollectors = []prometheus.Collector{
		codecValueSize,
	}

	labelRead  = prometheus.Labels{"call": "read"}
	labelWrite = prometheus.Labels{"call": "write"}

	metricsOnce sync.Once
)

// MessageReader is a reader wrapper that decodes CBOR-encoded Message structures.
type MessageReader struct {
	reader io.Reader
}

// Read deserializes a single CBOR-encoded Message from the underlying reader.
func (c *MessageReader) Read(msg interface{}) error {
	// Read 32-bit length prefix.
	rawLength := make([]byte, 4)
	if _, err := io.ReadAtLeast(c.reader, rawLength, 4); err != nil {
		return err
	}

	length := binary.BigEndian.Uint32(rawLength)
	codecValueSize.With(labelRead).Observe(float64(length))
	if length > maxMessageSize {
		return errMessageTooLarge
	}

	// Read message bytes.
	rawMessage := make([]byte, length)
	if _, err := io.ReadFull(c.reader, rawMessage); err != nil {
		return err
	}

	// Decode CBOR into given message.
	if err := Unmarshal(rawMessage, msg); err != nil {
		return err
	}

	return nil
}

// MessageWriter is a writer wrapper that encodes Messages structures to CBOR.
type MessageWriter struct {
	writer io.Writer
}

// Write serializes a single Message to CBOR and writes it to the underlying writer.
func (c *MessageWriter) Write(msg interface{}) error {
	// Encode into CBOR.
	data := Marshal(msg)
	length := len(data)
	codecValueSize.With(labelWrite).Observe(float64(length))
	if length > maxMessageSize {
		return errMessageTooLarge
	}

	// Write 32-bit length prefix and encoded data.
	rawLength := make([]byte, 4)
	binary.BigEndian.PutUint32(rawLength, uint32(length))
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
	metricsOnce.Do(func() {
		prometheus.MustRegister(codecCollectors...)
	})

	return &MessageCodec{
		MessageReader: MessageReader{reader: rw},
		MessageWriter: MessageWriter{writer: rw},
	}
}
