package client

import (
	"context"
	"crypto/x509"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/resolver/manual"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/service"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	txnscheduler "github.com/oasislabs/oasis-core/go/worker/compute/txnscheduler/api"
)

type watchRequest struct {
	id     *hash.Hash
	ctx    context.Context
	respCh chan *watchResult
}

func (w *watchRequest) send(res *watchResult) error {
	select {
	case <-w.ctx.Done():
		return context.Canceled
	case w.respCh <- res:
		return nil
	}
}

type watchResult struct {
	result                []byte
	err                   error
	newTxnschedulerClient txnscheduler.TransactionScheduler
}

type txnschedulerClientState struct {
	client            txnscheduler.TransactionScheduler
	conn              *grpc.ClientConn
	resolverCleanupCb func()
}

func (t *txnschedulerClientState) updateConnection(node *node.Node) error {
	// Clean-up previous resolvers and connections.
	if cleanup := t.resolverCleanupCb; cleanup != nil {
		cleanup()
	}
	if t.conn != nil {
		t.conn.Close()
	}

	// Setup resolver.
	nodeCert, err := node.Committee.ParseCertificate()
	if err != nil {
		return errors.Wrap(err, "client/watcher: failed to parse txnscheduler leader certificate")
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(nodeCert)

	creds := credentials.NewClientTLSFromCert(certPool, identity.CommonName)

	manualResolver, address, cleanup := manual.NewManualResolver()
	t.resolverCleanupCb = cleanup

	// Dial.
	conn, err := cmnGrpc.Dial(address, grpc.WithTransportCredentials(creds), grpc.WithBalancerName(roundrobin.Name)) //nolint: staticcheck
	if err != nil {
		return errors.Wrap(err, "client/watcher: failed to dial txnscheduler leader")
	}
	t.conn = conn

	t.client = txnscheduler.NewTransactionSchedulerClient(conn)

	var resolverState resolver.State
	for _, addr := range node.Committee.Addresses {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return nil
}

type blockWatcher struct {
	service.BaseBackgroundService

	common *clientCommon
	id     common.Namespace

	watched map[hash.Hash]*watchRequest
	newCh   chan *watchRequest

	txnschedulerClientState *txnschedulerClientState

	stopCh chan struct{}
}

func (w *blockWatcher) refreshCommittee(height int64) error {
	committees, err := w.common.scheduler.GetCommittees(w.common.ctx, &scheduler.GetCommitteesRequest{
		RuntimeID: w.id,
		Height:    height,
	})
	if err != nil {
		return err
	}

	var committee *scheduler.Committee
	for _, c := range committees {
		if c.Kind != scheduler.KindComputeTxnScheduler {
			continue
		}
		committee = c
		break
	}

	if committee == nil {
		return errors.New("client/watcher: no transaction scheduler committee after epoch transition")
	}

	var leaderNode *node.Node
	for _, node := range committee.Members {
		if node.Role != scheduler.Leader {
			continue
		}
		leaderNode, err = w.common.registry.GetNode(w.common.ctx, &registry.IDQuery{ID: node.PublicKey, Height: height})
		if err != nil {
			return err
		}
		break
	}
	if leaderNode == nil {
		return errors.New("client/watcher: no leader in new committee")
	}

	// Update txnscheduler leader connection and tell every client to resubmit.
	if err := w.txnschedulerClientState.updateConnection(leaderNode); err != nil {
		return err
	}
	for key, watch := range w.watched {
		res := &watchResult{
			newTxnschedulerClient: w.txnschedulerClientState.client,
		}
		if watch.send(res) != nil {
			delete(w.watched, key)
		}
	}
	return nil
}

func (w *blockWatcher) checkBlock(blk *block.Block) {
	if blk.Header.IORoot.IsEmpty() {
		return
	}

	ctx := w.common.ctx
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		Hash:      blk.Header.IORoot,
	}

	tree := transaction.NewTree(w.common.storage, ioRoot)
	defer tree.Close()

	// Check if there's anything interesting in this block.
	var txHashes []hash.Hash
	for txHash := range w.watched {
		txHashes = append(txHashes, txHash)
	}

	matches, err := tree.GetTransactionMultiple(ctx, txHashes)
	if err != nil {
		w.Logger.Error("can't get block I/O from storage", "err", err)
		return
	}

	for txHash, tx := range matches {
		watch := w.watched[txHash]
		res := &watchResult{
			result: tx.Output,
		}

		// Ignore errors, the watch is getting deleted anyway.
		_ = watch.send(res)
		close(watch.respCh)
		delete(w.watched, txHash)
	}
}

func (w *blockWatcher) watch() {
	defer func() {
		close(w.newCh)
		for _, watch := range w.watched {
			close(watch.respCh)
		}
		w.BaseBackgroundService.Stop()
	}()

	// If we were just started, refresh the committee information from any
	// block, otherwise just from epoch transition blocks.
	gotFirstBlock := false
	// Start watching roothash blocks.
	blocks, blocksSub, err := w.common.roothash.WatchBlocks(w.id)
	if err != nil {
		w.Logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

	for {
		var current *block.Block
		var height int64

		// Wait for stuff to happen.
		select {
		case blk := <-blocks:
			current = blk.Block
			height = blk.Height

		case newWatch := <-w.newCh:
			w.watched[*newWatch.id] = newWatch
			if w.txnschedulerClientState.client != nil {
				res := &watchResult{
					newTxnschedulerClient: w.txnschedulerClientState.client,
				}
				if newWatch.send(res) != nil {
					delete(w.watched, *newWatch.id)
				}
			}

		case <-w.stopCh:
			w.Logger.Info("stop requested, aborting watcher")
			return
		case <-w.common.ctx.Done():
			w.Logger.Info("context cancelled, aborting watcher")
			return
		}

		if current == nil || current.Header.HeaderType == block.RoundFailed {
			continue
		}

		// Find a new committee leader.
		if current.Header.HeaderType == block.EpochTransition || !gotFirstBlock {
			if err := w.refreshCommittee(height); err != nil {
				w.Logger.Error("error getting new committee data, waiting for next epoch", "err", err)
				continue
			}

		}
		gotFirstBlock = true

		// Check this new block.
		if current.Header.HeaderType == block.Normal {
			w.checkBlock(current)
		}
	}
}

// Start starts a new per-runtime block watcher.
func (w *blockWatcher) Start() error {
	go w.watch()
	return nil
}

// Stop initiates watcher shutdown.
func (w *blockWatcher) Stop() {
	close(w.stopCh)
}

func newWatcher(common *clientCommon, id common.Namespace) (*blockWatcher, error) {
	svc := service.NewBaseBackgroundService("client/watcher")
	watcher := &blockWatcher{
		BaseBackgroundService:   *svc,
		common:                  common,
		id:                      id,
		txnschedulerClientState: &txnschedulerClientState{},
		watched:                 make(map[hash.Hash]*watchRequest),
		newCh:                   make(chan *watchRequest),
		stopCh:                  make(chan struct{}),
	}
	return watcher, nil
}
