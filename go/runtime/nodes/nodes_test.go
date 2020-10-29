package nodes

import (
	"sync"
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

const recvTimeout = 1 * time.Second

type mockDescriptorLookup struct {
	sync.Mutex

	nodes         map[signature.PublicKey]*node.Node
	nodesByPeerID map[signature.PublicKey]*node.Node
	tags          map[signature.PublicKey][]string

	notifier *pubsub.Broker
}

func (m *mockDescriptorLookup) Lookup(id signature.PublicKey) *node.Node {
	m.Lock()
	defer m.Unlock()
	return m.nodes[id]
}

func (m *mockDescriptorLookup) LookupByPeerID(id signature.PublicKey) *node.Node {
	m.Lock()
	defer m.Unlock()
	return m.nodesByPeerID[id]
}

func (m *mockDescriptorLookup) LookupTags(id signature.PublicKey) []string {
	m.Lock()
	defer m.Unlock()
	return m.tags[id]
}

func (m *mockDescriptorLookup) GetNodes() []*node.Node {
	m.Lock()
	defer m.Unlock()
	nodes := make([]*node.Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodes = append(nodes, n)
	}

	return nodes
}

func (m *mockDescriptorLookup) WatchNodeUpdates() (<-chan *NodeUpdate, pubsub.ClosableSubscription, error) {
	sub := m.notifier.Subscribe()
	ch := make(chan *NodeUpdate)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (m *mockDescriptorLookup) Versioned() bool {
	return false
}

func TestFilteredNodeLookup(t *testing.T) {
	require := require.New(t)

	var pk1, pk2, pk3, pk4 signature.PublicKey
	_ = pk1.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")
	_ = pk2.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000001")
	_ = pk3.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000002")
	_ = pk4.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000003")

	n2 := &node.Node{ID: pk2}
	mock := &mockDescriptorLookup{
		nodes: map[signature.PublicKey]*node.Node{
			pk1: {
				ID: pk1,
			},
			pk2: n2,
			pk3: {
				ID: pk3,
			},
		},
		nodesByPeerID: map[signature.PublicKey]*node.Node{
			pk1: {
				ID: pk1,
			},
			pk2: n2,
			pk3: {
				ID: pk3,
			},
		},
		tags: map[signature.PublicKey][]string{
			pk1: {"tag1", "tag2", "tag3"},
			pk2: {"tag2", "tag3"},
			pk3: {},
		},
	}
	mock.notifier = pubsub.NewBrokerEx(func(ch channels.Channel) {
		ch.In() <- &NodeUpdate{Reset: true}
		for _, n := range mock.nodes {
			ch.In() <- &NodeUpdate{Update: n}
		}
	})

	filtered := NewFilteredNodeLookup(mock,
		WithAllFilters(
			IgnoreNodeFilter(pk1),
			TagFilter("tag2"),
		),
	)

	// Test GetNodes.
	require.EqualValues([]*node.Node{n2}, filtered.GetNodes(), "GetNodes() should only return the node matching filters")

	// Test Lookup.
	require.Equal(n2, filtered.Lookup(pk2), "Lookup() should correctly return node matching filters")
	require.Nil(filtered.Lookup(pk1), "Lookup() should not return node not matching filters")

	// Test LookupByPeerID
	require.Equal(n2, filtered.LookupByPeerID(pk2), "LookupByPeerID() should correctly return node matching filters")
	require.Nil(filtered.LookupByPeerID(pk1), "LookupByPeerID() should not return node not matching filters")

	// Test LookupTags.
	require.EqualValues([]string{"tag2", "tag3"}, filtered.LookupTags(pk2), "LookupTags() should correctly return tags for node")
	require.EqualValues([]string{"tag1", "tag2", "tag3"}, filtered.LookupTags(pk1), "LookupTags() should return tags for node not matching filters")

	// Test WatchNodeUpdates.
	ch, sub, err := filtered.WatchNodeUpdates()
	require.NoError(err)
	defer sub.Close()

	// On subscribe receive the reset and n2 node update events.
	select {
	case ev := <-ch:
		require.EqualValues(&NodeUpdate{Reset: true}, ev, "expected NodeUpdate.Reset event")
	case <-time.After(recvTimeout):
		t.Fatal("failed to receive initial reset event")
	}
	select {
	case ev := <-ch:
		require.EqualValues(&NodeUpdate{Update: n2}, ev, "expected NodeUpdate.Update event")
	case <-time.After(recvTimeout):
		t.Fatal("failed to receive initial reset event")
	}

	type testCase struct {
		test          func()
		expectedEvent *NodeUpdate
		msg           string
	}
	for _, tc := range []testCase{
		{
			// Add pk4, matching filters -> should receive update event.
			test: func() {
				mock.Lock()
				defer mock.Unlock()
				mock.tags[pk4] = []string{"tag2"}
				mock.notifier.Broadcast(&NodeUpdate{
					Update: &node.Node{
						ID: pk4,
					},
				})
			},
			expectedEvent: &NodeUpdate{
				Update: &node.Node{
					ID: pk4,
				},
			},
			msg: "Added pk4 matching filters. Expecting update event.",
		},
		{
			// Add tag to pk3 -> should receive update event.
			test: func() {
				mock.Lock()
				defer mock.Unlock()
				mock.tags[pk3] = []string{"tag2"}
				mock.notifier.Broadcast(&NodeUpdate{
					Update: &node.Node{
						ID: pk3,
					},
				})
			},
			expectedEvent: &NodeUpdate{
				Update: &node.Node{
					ID: pk3,
				},
			},
			msg: "Added matching tag to pk3. Expecting update event.",
		},
		{
			// Remove tag from pk2 -> should receive delete event.
			test: func() {
				mock.Lock()
				defer mock.Unlock()
				mock.tags[pk2] = []string{}
				mock.notifier.Broadcast(&NodeUpdate{
					Update: &node.Node{
						ID: pk2,
					},
				})
			},
			expectedEvent: &NodeUpdate{
				Delete: &pk2,
			},
			msg: "Removed matching tag from pk2. Expecting delete event.",
		},
		{
			// Update pk2 not matching filters -> should receive no event.
			test: func() {
				mock.Lock()
				defer mock.Unlock()
				mock.tags[pk2] = []string{"tag42"}
				mock.notifier.Broadcast(&NodeUpdate{
					Update: &node.Node{
						ID: pk2,
					},
				})
			},
			expectedEvent: nil,
			msg:           "Adding non-matching tag to pk2. Expecting no event.",
		},
	} {
		// Run the test code.
		tc.test()

		// Assert expected event is received.
		select {
		case res := <-ch:
			switch tc.expectedEvent {
			case nil:
				t.Fatalf("Expected no event, received event: %v, for test: '%s'", res, tc.msg)
			default:
				require.EqualValues(tc.expectedEvent, res, tc.msg)
			}
		case <-time.After(recvTimeout):
			switch tc.expectedEvent {
			case nil:
				// Expected.
			default:
				t.Fatalf("failed to receive expected event: %v, for test: '%s'", tc.expectedEvent, tc.msg)
			}
		}
	}
}
