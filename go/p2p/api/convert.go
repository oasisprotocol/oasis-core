package api

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// PublicKeyToPeerID converts a public key to a peer identifier.
func PublicKeyToPeerID(pk signature.PublicKey) (core.PeerID, error) {
	pubKey, err := publicKeyToPubKey(pk)
	if err != nil {
		return "", err
	}

	id, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	return id, nil
}

// PublicKeyMapToPeerIDs converts a map of public keys to a list of peer identifiers.
func PublicKeyMapToPeerIDs(pks map[signature.PublicKey]struct{}) ([]core.PeerID, error) {
	ids := make([]core.PeerID, 0, len(pks))
	for pk := range pks {
		id, err := PublicKeyToPeerID(pk)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// AddrInfosFromConsensusAddrs converts string consensus addresses to addr infos.
func AddrInfosFromConsensusAddrs(addrs []string) ([]peer.AddrInfo, error) {
	peerMap := make(map[core.PeerID]*peer.AddrInfo)
	for _, s := range addrs {
		// Peer addresses are in the format pubkey@IP:port, because we use a similar format
		// elsewhere and it's easier for users to understand than a multiaddr.
		var addr node.ConsensusAddress
		if err := addr.UnmarshalText([]byte(s)); err != nil {
			return nil, fmt.Errorf("malformed address (expected pubkey@IP:port): %w", err)
		}

		pid, err := PublicKeyToPeerID(addr.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid public key (%s): %w", addr.ID, err)
		}

		ma, err := addr.Address.MultiAddress()
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to multi address (%s): %w", addr, err)
		}

		// If we already have this peer ID, append to its addresses.
		if info, ok := peerMap[pid]; ok {
			info.Addrs = append(info.Addrs, ma)
			continue
		}

		// Fresh entry.
		info := peer.AddrInfo{
			ID:    pid,
			Addrs: []multiaddr.Multiaddr{ma},
		}
		peerMap[pid] = &info
	}

	peers := make([]peer.AddrInfo, 0, len(peerMap))
	for _, info := range peerMap {
		peers = append(peers, *info)
	}

	return peers, nil
}

// AddrInfoToString converts AddressInfo to a list of p2p string multiaddresses.
//
// For example, an address info with ID 1234 and multiaddresses /ip4/127.0.0.1/tcp/8080 and
// /ip6/::1/tcp/8080 would be converted to a list ["/ip4/127.0.0.1/tcp/8080/p2p/1234",
// "/ip6/::1/tcp/8080/p2p/1234"].
func AddrInfoToString(info peer.AddrInfo) []string {
	id := info.ID.String()
	addrs := make([]string, len(info.Addrs))
	for i, a := range info.Addrs {
		addrs[i] = fmt.Sprintf("%s/p2p/%s", a.String(), id)
	}
	return addrs
}
