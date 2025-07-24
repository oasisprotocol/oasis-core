package committee

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	mkvsCp "github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

func TestSortCheckpoints(t *testing.T) {
	cp1 := &checkpoint{
		Metadata: &mkvsCp.Metadata{
			Root: node.Root{
				Version: 2,
			},
		},
		peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback(), rpc.NewNopPeerFeedback()},
	}
	cp2 := &checkpoint{
		Metadata: &mkvsCp.Metadata{
			Root: node.Root{
				Version: 2,
			},
		},
		peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback()},
	}
	cp3 := &checkpoint{
		Metadata: &mkvsCp.Metadata{
			Root: node.Root{
				Version: 1,
			},
		},
		peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback(), rpc.NewNopPeerFeedback()},
	}
	cp4 := &checkpoint{
		Metadata: &mkvsCp.Metadata{
			Root: node.Root{
				Version: 1,
			},
		},
		peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback()},
	}

	s := []*checkpoint{cp2, cp3, cp4, cp1}

	sortCheckpoints(s)

	assert.Equal(t, s, []*checkpoint{cp1, cp2, cp3, cp4})
}
