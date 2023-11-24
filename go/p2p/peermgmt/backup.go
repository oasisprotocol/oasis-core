package peermgmt

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/scheduling"
	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
)

const (
	// peerstoreBucketName is the name of the bucket in which backup data is stored.
	peerstoreBucketName = "p2p/peer_manager/peerstore"

	// peerstoreBucketKey is the bucket key under which peers from the peerstore are stored.
	peerstoreBucketKey = "peers"

	// peerstoreBackupTaskName is the name of the task responsible for periodical backups.
	peerstoreBackupTaskName = "peerstore-backup"

	// peerstoreNamespace is the namespace under which peers are stored in the backup.
	peerstoreNamespace = ""

	// backupDelay is the initial time delay for backups.
	backupDelay = 15 * time.Minute

	// backupInterval is the time interval between backups.
	backupInterval = 15 * time.Minute
)

type peerstoreBackup struct {
	logger *logging.Logger

	store           peerstore.Peerstore
	backupBackend   backup.Backend
	backupScheduler scheduling.Scheduler
}

func newPeerstoreBackup(ps peerstore.Peerstore, b backup.Backend) *peerstoreBackup {
	l := logging.GetLogger("p2p/peer-manager/backup")

	pb := peerstoreBackup{
		logger:        l,
		store:         ps,
		backupBackend: b,
	}

	pb.backupScheduler = scheduling.NewFixedRateScheduler(backupDelay, backupInterval)
	pb.backupScheduler.AddTask(peerstoreBackupTaskName, pb.backup)

	return &pb
}

func (b *peerstoreBackup) backup(ctx context.Context) error {
	b.logger.Debug("backing up peers")

	peers := b.store.PeersWithAddrs()
	infos := make([]peer.AddrInfo, 0, len(peers))
	for _, p := range peers {
		infos = append(infos, b.store.PeerInfo(p))
	}
	nsPeers := map[string][]peer.AddrInfo{
		peerstoreNamespace: infos,
	}

	err := b.backupBackend.Backup(ctx, nsPeers)
	if err != nil {
		b.logger.Error("failed to backup peers",
			"err", err,
		)
		return err
	}

	return nil
}

func (b *peerstoreBackup) restore(ctx context.Context) error {
	b.logger.Debug("restoring peers")

	peers, err := b.backupBackend.Restore(ctx)
	if err != nil {
		b.logger.Error("failed to restore peers",
			"err", err,
		)
		return err
	}

	for _, info := range peers[peerstoreNamespace] {
		// Make sure to add, not set, the address to avoid overwriting the TTL.
		b.store.AddAddrs(info.ID, info.Addrs, peerstore.RecentlyConnectedAddrTTL)
	}

	return nil
}

func (b *peerstoreBackup) start() {
	b.backupScheduler.Start()
}

func (b *peerstoreBackup) stop() {
	b.backupScheduler.Stop()
}
