package protocol

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCodecRoundTrip(t *testing.T) {
	msg := Message{
		ID:          0,
		MessageType: MessageRequest,
		Body: Body{
			WorkerPingRequest: &Empty{},
		},
	}

	var buffer bytes.Buffer
	codec := NewMessageCodec(&buffer)
	err := codec.Write(&msg)
	require.NoError(t, err, "Write (1st)")

	err = codec.Write(&msg)
	require.NoError(t, err, "Write (2nd)")

	var decodedMsg1 Message
	err = codec.Read(&decodedMsg1)
	require.NoError(t, err, "Read (1st)")
	require.EqualValues(t, msg, decodedMsg1, "Decoded message must be equal to source message")

	var decodedMsg2 Message
	err = codec.Read(&decodedMsg2)
	require.NoError(t, err, "Read (2nd)")
	require.EqualValues(t, msg, decodedMsg2, "Decoded message must be equal to source message")
}
