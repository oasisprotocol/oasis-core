// Package backup provides tools for backing up peers.
package backup

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Backend is an interface used to backup and restore peer identities and addresses.
type Backend interface {
	// Delete permanently removes all peers from the backup.
	Delete(ctx context.Context) error

	// Backup stores gives peers possibly overwriting the last backup.
	Backup(ctx context.Context, nsPeers map[string][]peer.AddrInfo) error

	// Restore returns peers from the last backup.
	Restore(ctx context.Context) (map[string][]peer.AddrInfo, error)
}
