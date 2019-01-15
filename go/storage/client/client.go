package client

import (
	"io"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "client"

	// Address to connect to with the storage client.
	cfgClientAddress = "storage.client.address"
)

var (
	_ api.Backend = (*storageClientBackend)(nil)
)

type storageClientBackend struct {
	logger *logging.Logger
	client storage.StorageClient
	conn   *grpc.ClientConn
}

func (b *storageClientBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	var req storage.GetRequest

	req.Id = key[:]

	resp, err := b.client.Get(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetData(), nil
}

func (b *storageClientBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var req storage.GetBatchRequest

	req.Ids = make([][]byte, 0, len(keys))
	for _, v := range keys {
		req.Ids = append(req.Ids, v[:])
	}

	resp, err := b.client.GetBatch(ctx, &req)
	if err != nil {
		return nil, err
	}

	return resp.GetData(), nil
}

func (b *storageClientBackend) Insert(ctx context.Context, value []byte, expiration uint64) error {
	var req storage.InsertRequest

	req.Data = value
	req.Expiry = expiration

	_, err := b.client.Insert(ctx, &req)
	return err
}

func (b *storageClientBackend) InsertBatch(ctx context.Context, values []api.Value) error {
	var req storage.InsertBatchRequest

	req.Items = make([]*storage.InsertRequest, 0, len(values))
	for _, v := range values {
		value := v.Data
		exp := v.Expiration

		req.Items = append(req.Items, &storage.InsertRequest{
			Data:   value,
			Expiry: exp,
		})
	}

	_, err := b.client.InsertBatch(ctx, &req)
	return err
}

func (b *storageClientBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	keys, err := b.client.GetKeys(ctx, &storage.GetKeysRequest{})
	if err != nil {
		return nil, err
	}

	kiCh := make(chan *api.KeyInfo)

	go func() {
		defer close(kiCh)

		for {
			resp, err := keys.Recv()

			switch err {
			case nil:
			case io.EOF:
				return
			}

			ki := &api.KeyInfo{
				Expiration: epochtime.EpochTime(resp.GetExpiry()),
			}
			copy(ki.Key[:], resp.GetKey())

			select {
			case kiCh <- ki:
			case <-ctx.Done():
				return
			}
		}
	}()

	return kiCh, nil
}

func (b *storageClientBackend) Cleanup() {
	b.conn.Close()
}

func (b *storageClientBackend) Initialized() <-chan struct{} {
	initCh := make(chan struct{})
	close(initCh)
	return initCh
}

func New() (api.Backend, error) {
	conn, err := grpc.Dial(viper.GetString(cfgClientAddress), grpc.WithInsecure())

	if err != nil {
		return nil, err
	}

	client := storage.NewStorageClient(conn)

	b := &storageClientBackend{
		logger: logging.GetLogger("storage/client"),
		client: client,
		conn:   conn,
	}

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgClientAddress, "localhost:42261", "Address of node to connect to with the storage client")
	}

	for _, v := range []string{
		cfgClientAddress,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
