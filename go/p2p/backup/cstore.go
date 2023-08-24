package backup

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
)

var _ Backend = (*commonStoreBackend)(nil)

// commonStoreBackend uses the common store to backup and restore peers.
type commonStoreBackend struct {
	logger *logging.Logger

	bucket *persistent.ServiceStore // A handle to a bucket where peers are stored.
	key    string                   // A key under which peers are stored in the bucket.
}

// NewCommonStoreBackend creates a new common store backend.
//
// The name of the bucket and the key under which peers are stored should be unique to avoid
// backups to be overwritten.
func NewCommonStoreBackend(cs *persistent.CommonStore, bucket string, key string) Backend {
	l := logging.GetLogger("p2p/backup/common-store-backend")

	var b *persistent.ServiceStore
	if cs != nil {
		b = cs.GetServiceStore(bucket)
	}

	return &commonStoreBackend{
		logger: l,
		bucket: b,
		key:    key,
	}
}

// Delete implements PeerBackup.
func (b *commonStoreBackend) Delete(context.Context) error {
	if b.bucket == nil {
		return nil
	}

	return b.bucket.Delete([]byte(b.key))
}

// Backup implements PeerBackup.
func (b *commonStoreBackend) Backup(_ context.Context, nsPeers map[string][]peer.AddrInfo) error {
	if b.bucket == nil {
		return nil
	}

	// Convert addresses to json, skipping empty ones.
	data := make(map[string][][]byte)
	for ns, infos := range nsPeers {
		jsons := make([][]byte, 0, len(infos))
		for _, info := range infos {
			if len(info.Addrs) == 0 {
				continue
			}
			json, err := info.MarshalJSON()
			if err != nil {
				return err
			}
			jsons = append(jsons, json)
		}
		if len(jsons) == 0 {
			continue
		}
		data[ns] = jsons
	}

	// Don't override the last backup if not needed.
	if len(data) == 0 {
		return nil
	}

	// Store addresses.
	if err := b.bucket.PutCBOR([]byte(b.key), data); err != nil {
		return err
	}

	return nil
}

// Restore implements PeerBackup.
func (b *commonStoreBackend) Restore(_ context.Context) (map[string][]peer.AddrInfo, error) {
	if b.bucket == nil {
		return map[string][]peer.AddrInfo{}, nil
	}

	// Restore addresses.
	data := make(map[string][][]byte)
	if err := b.bucket.GetCBOR([]byte(b.key), &data); err != nil {
		switch err {
		case persistent.ErrNotFound:
			return map[string][]peer.AddrInfo{}, nil
		default:
			return nil, err
		}
	}

	// Convert them from json.
	nsPeers := make(map[string][]peer.AddrInfo)
	for ns, jsons := range data {
		infos := make([]peer.AddrInfo, len(jsons))
		for i := range jsons {
			err := infos[i].UnmarshalJSON(jsons[i])
			if err != nil {
				return nil, err
			}
		}
		nsPeers[ns] = infos
	}

	return nsPeers, nil
}
