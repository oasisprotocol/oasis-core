package peermgmt

import (
	"context"
	"math/rand"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
)

const (
	// storeBucketName is the name of the bucket in which backup data is stored.
	storeBucketName = "p2p/peer_manager"

	// storePeerstoreKey is the bucket key under which peers from the peerstore are stored.
	storePeerstoreKey = "peerstore"

	// backupStartupDelay is the startup time delay for backups.
	backupStartupDelay = 15 * time.Minute

	// backupInterval is the time interval between backups.
	backupInterval = 15 * time.Minute

	// maxRestorePeers is the maximum number of peers connected on startup from the backup.
	maxRestorePeers = 100
)

type peerstoreBackup struct {
	logger *logging.Logger

	host host.Host

	store   *persistent.CommonStore
	storeCh chan struct{}

	startOne cmSync.One
}

func newPeerstoreBackup(h host.Host, cs *persistent.CommonStore) *peerstoreBackup {
	l := logging.GetLogger("p2p/peer-manager/backup")

	return &peerstoreBackup{
		logger:   l,
		host:     h,
		store:    cs,
		storeCh:  make(chan struct{}, 1),
		startOne: cmSync.NewOne(),
	}
}

// save persists peers to the store.
func (b *peerstoreBackup) save() error {
	if b.store == nil {
		return nil
	}

	// Allow only one save/load at a time.
	b.storeCh <- struct{}{}
	defer func() { <-b.storeCh }()

	// Save only connected peers.
	peers := b.host.Network().Peers()

	if len(peers) == 0 {
		return nil
	}

	b.logger.Debug("storing peers",
		"count", len(peers),
	)

	infos := make([][]byte, 0, len(peers))
	for _, p := range peers {
		info := b.host.Peerstore().PeerInfo(p)
		if len(info.Addrs) == 0 {
			continue
		}

		json, err := info.MarshalJSON()
		if err != nil {
			return err
		}

		infos = append(infos, json)
	}

	// Persist addresses.
	bucket, err := b.store.GetServiceStore(storeBucketName)
	if err != nil {
		return err
	}
	if err = bucket.PutCBOR([]byte(storePeerstoreKey), infos); err != nil {
		return err
	}

	return nil
}

// load loads peers from the store.
func (b *peerstoreBackup) load() ([]*peer.AddrInfo, error) {
	if b.store == nil {
		return []*peer.AddrInfo{}, nil
	}

	// Allow only one save/load at a time.
	b.storeCh <- struct{}{}
	defer func() { <-b.storeCh }()

	b.logger.Debug("loading peers")

	// Load addresses in json form.
	bucket, err := b.store.GetServiceStore(storeBucketName)
	if err != nil {
		return nil, err
	}
	var jsons [][]byte
	if err = bucket.GetCBOR([]byte(storePeerstoreKey), &jsons); err != nil {
		return nil, err
	}

	// Convert them.
	infos := make([]*peer.AddrInfo, len(jsons))
	for i, json := range jsons {
		var info peer.AddrInfo
		if err = info.UnmarshalJSON(json); err != nil {
			return nil, err
		}
		infos[i] = &info
	}

	return infos, nil
}

// start starts a background task which periodically backups peers to the store. If a backup
// is already in progress, this is a noop operation.
func (b *peerstoreBackup) start() {
	b.startOne.TryStart(b.run)
}

// stop stops the backup service, if one is running.
func (b *peerstoreBackup) stop() {
	b.startOne.TryStop()
}

// run periodically backups peers to the store. If a backup is already in progress, this method will
// wait for it to finish.
func (b *peerstoreBackup) run(ctx context.Context) {
	select {
	case <-time.After(backupStartupDelay):
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(backupInterval)
	defer ticker.Stop()

	for {
		if err := b.save(); err != nil {
			b.logger.Error("failed to backup peers",
				"err", err,
			)
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// restore loads peers from the backup and connects to few of them.
func (b *peerstoreBackup) restore(ctx context.Context, c *peerConnector) {
	infos, err := b.load()
	if err != nil {
		b.logger.Error("failed to load peers from the backup",
			"err", err,
		)
		return
	}

	b.logger.Debug("connecting to peers from the backup",
		"count", len(infos),
		"limit", maxRestorePeers,
	)

	// Connect to a random subset.
	rand.Shuffle(len(infos), func(i, j int) {
		infos[i], infos[j] = infos[j], infos[i]
	})

	c.connectMany(ctx, infos, maxRestorePeers)
}
