package committee

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/sync"
)

func TestSortCheckpoints(t *testing.T) {
	cp1 := &sync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 2,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback(), rpc.NewNopPeerFeedback()},
	}
	cp2 := &sync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 2,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback()},
	}
	cp3 := &sync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 1,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback(), rpc.NewNopPeerFeedback()},
	}
	cp4 := &sync.Checkpoint{
		Metadata: &checkpoint.Metadata{
			Root: node.Root{
				Version: 1,
			},
		},
		Peers: []rpc.PeerFeedback{rpc.NewNopPeerFeedback()},
	}

	s := []*sync.Checkpoint{cp2, cp3, cp4, cp1}

	sortCheckpoints(s)

	assert.Equal(t, s, []*sync.Checkpoint{cp1, cp2, cp3, cp4})
}
