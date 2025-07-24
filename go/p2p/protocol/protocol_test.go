package protocol

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

func TestProtocolID(t *testing.T) {
	chainContext := "d19ea2397fde0eba4b429f05443cced640c1f866c6df43f07132f1cdf6516c84" // #nosec G101
	version := version.Version{Major: 1, Minor: 2, Patch: 3}

	t.Run("NewProtocolID", func(t *testing.T) {
		require := require.New(t)

		protocolID := "consensus"
		expected := protocol.ID(
			"/oasis/d19ea2397fde0eba4b429f05443cced640c1f866c6df43f07132f1cdf6516c84/consensus/1.0.0",
		)

		require.Equal(expected, NewProtocolID(chainContext, protocolID, version))
	})

	t.Run("NewRuntimeProtocolID", func(t *testing.T) {
		require := require.New(t)

		protocolID := "runtime"

		var runtimeID common.Namespace
		err := runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
		require.NoError(err, "failed to unmarshal runtime id")

		expected := protocol.ID(
			"/oasis/d19ea2397fde0eba4b429f05443cced640c1f866c6df43f07132f1cdf6516c84/runtime/8000000000000000000000000000000000000000000000000000000000000000/1.0.0",
		)

		require.Equal(expected, NewRuntimeProtocolID(chainContext, runtimeID, protocolID, version))
	})

	t.Run("NewTopicIDForRuntime", func(t *testing.T) {
		require := require.New(t)

		kind := api.TopicKind("topic")

		var runtimeID common.Namespace
		err := runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
		require.NoError(err, "failed to unmarshal runtime id")

		expected := "oasis/d19ea2397fde0eba4b429f05443cced640c1f866c6df43f07132f1cdf6516c84/topic/8000000000000000000000000000000000000000000000000000000000000000/1.0.0"

		require.Equal(expected, NewTopicIDForRuntime(chainContext, runtimeID, kind, version))
	})

	t.Run("ValidateProtocolID", func(_ *testing.T) {
		r := NewRegistry()
		r.ValidateProtocolID("protocol-1")
		r.ValidateProtocolID("protocol-2")
	})

	t.Run("ValidateProtocolID panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("validate protocol id should fail")
			}
		}()
		r := NewRegistry()
		r.ValidateProtocolID("protocol")
		r.ValidateProtocolID("protocol")
	})
}
