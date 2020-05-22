package cbor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

type message struct {
	Number uint64
}

func TestCodecRoundTrip(t *testing.T) {
	msg := message{
		Number: 42,
	}

	var buffer bytes.Buffer
	codec := NewMessageCodec(&buffer, t.Name())
	err := codec.Write(&msg)
	require.NoError(t, err, "Write (1st)")

	err = codec.Write(&msg)
	require.NoError(t, err, "Write (2nd)")

	var decodedMsg1 message
	err = codec.Read(&decodedMsg1)
	require.NoError(t, err, "Read (1st)")
	require.EqualValues(t, msg, decodedMsg1, "Decoded message must be equal to source message")

	var decodedMsg2 message
	err = codec.Read(&decodedMsg2)
	require.NoError(t, err, "Read (2nd)")
	require.EqualValues(t, msg, decodedMsg2, "Decoded message must be equal to source message")
}

func TestCodecOversized(t *testing.T) {
	require := require.New(t)

	var buffer bytes.Buffer
	codec := NewMessageCodec(&buffer, t.Name())

	err := codec.Write(42)
	require.NoError(err, "Write")

	// Corrupt the buffer to include a huge length.
	binary.BigEndian.PutUint32(buffer.Bytes()[:4], maxMessageSize+1)

	var x int
	err = codec.Read(&x)
	require.Error(err, "Read should fail with oversized message")
	require.EqualValues(errMessageTooLarge, err)
}

func TestCodecMalformed(t *testing.T) {
	require := require.New(t)

	var buffer bytes.Buffer
	codec := NewMessageCodec(&buffer, t.Name())

	err := codec.Write(42)
	require.NoError(err, "Write")

	// Corrupt the buffer to include an incorrect length (larger than what is really there).
	binary.BigEndian.PutUint32(buffer.Bytes()[:4], 1024)

	var x int
	err = codec.Read(&x)
	require.Error(err, "Read should fail with malformed message")
	require.EqualValues(errMessageMalformed, err)
}
