package peermgmt

import (
	"sync"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/connmgr"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

type peerTagger struct {
	cmgr connmgr.ConnManager

	mu   sync.Mutex
	tags map[api.ImportanceKind]map[common.Namespace]map[core.PeerID]struct{}
}

func newPeerTagger(m connmgr.ConnManager) *peerTagger {
	return &peerTagger{
		cmgr: m,
		tags: make(map[api.ImportanceKind]map[common.Namespace]map[core.PeerID]struct{}),
	}
}

func (t *peerTagger) SetPeerImportance(kind api.ImportanceKind, runtimeID common.Namespace, pids []core.PeerID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tags[kind] == nil {
		t.tags[kind] = make(map[common.Namespace]map[core.PeerID]struct{})
	}
	previousPeers := t.tags[kind][runtimeID]
	t.tags[kind][runtimeID] = make(map[core.PeerID]struct{})

	for _, pid := range pids {
		t.cmgr.TagPeer(pid, kind.Tag(runtimeID), kind.TagValue())
		t.tags[kind][runtimeID][pid] = struct{}{}
		delete(previousPeers, pid)
	}

	// Clear importance for any previous nodes that are no longer considered important.
	for peerID := range previousPeers {
		t.cmgr.UntagPeer(peerID, kind.Tag(runtimeID))
	}
}
