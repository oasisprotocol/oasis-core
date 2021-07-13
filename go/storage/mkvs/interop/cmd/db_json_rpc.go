package cmd

import (
	"context"
	"net"
	"net/rpc"
	"sync"

	"github.com/powerman/rpc-codec/jsonrpc2"

	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type dbRPCService struct {
	ln net.Listener

	db *Database

	svrCh  chan struct{}
	quitCh chan struct{}
}

func (svc *dbRPCService) Name() string {
	return "protocol_server"
}

func (svc *dbRPCService) Start() error {
	svr := rpc.NewServer()
	if err := svr.Register(svc.db); err != nil {
		return err
	}

	go func() {
		defer close(svc.svrCh)

		var wg sync.WaitGroup
		for {
			conn, err := svc.ln.Accept()
			if err != nil {
				break
			}
			wg.Add(1)

			go func() {
				defer func() {
					_ = conn.Close()
					wg.Done()
				}()

				codec := jsonrpc2.NewServerCodec(conn, svr)
				svr.ServeCodec(codec)
			}()
		}
		wg.Wait()
	}()

	return nil
}

func (svc *dbRPCService) Stop() {
	defer close(svc.quitCh)

	_ = svc.ln.Close()
	<-svc.svrCh
}

func (svc *dbRPCService) Quit() <-chan struct{} {
	return svc.quitCh
}

func (svc *dbRPCService) Cleanup() {}

func newDbRPCService(
	ln net.Listener,
	backend storage.Backend,
) *dbRPCService {
	return &dbRPCService{
		ln: ln,
		db: &Database{
			ctx:   context.Background(),
			inner: backend,
		},
	}
}

type Database struct {
	ctx   context.Context
	inner storage.Backend
}

type ApplyResponse struct {
	Receipts []*storage.Receipt `json:"receipts"`
}

func (db *Database) Apply(request storage.ApplyRequest, response *ApplyResponse) error {
	resp, err := db.inner.Apply(db.ctx, &request)
	if err == nil {
		response.Receipts = resp
	}
	return err
}

func (db *Database) SyncGet(request storage.GetRequest, response *storage.ProofResponse) error {
	resp, err := db.inner.SyncGet(db.ctx, &request)
	if err == nil {
		*response = *resp
	}
	return err
}

func (db *Database) SyncGetPrefixes(request storage.GetPrefixesRequest, response *storage.ProofResponse) error {
	resp, err := db.inner.SyncGetPrefixes(db.ctx, &request)
	if err == nil {
		*response = *resp
	}
	return err
}

func (db *Database) SyncIterate(request storage.IterateRequest, response *storage.ProofResponse) error {
	resp, err := db.inner.SyncIterate(db.ctx, &request)
	if err == nil {
		*response = *resp
	}
	return err
}
