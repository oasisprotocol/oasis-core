package abci

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTimerKey(t *testing.T) {
	timer := timerState{
		app:      0x42,
		kind:     0x21,
		id:       []byte("test timer id"),
		deadline: 1571157805,
		data:     []byte("timer data"),
	}

	key := timer.getKey()
	// See timerKeyFmt for the key format.
	require.EqualValues(t, "f0000000005da5f72d4221746573742074696d6572206964", hex.EncodeToString(key))

	var dec timerState
	dec.fromKeyValue(key, timer.data)

	require.EqualValues(t, timer, dec, "timer state must round-trip")
}
