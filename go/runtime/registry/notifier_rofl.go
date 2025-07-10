package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	rofl "github.com/oasisprotocol/oasis-core/go/runtime/rofl/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

const (
	// roflNotifyTimeout is the maximum amount of time runtime notification handling can take.
	roflNotifyTimeout = 2 * time.Second
)

// ROFLNotifier notifies ROFL components about new runtime blocks and events.
type ROFLNotifier struct {
	host     *composite.Host
	notifier *RuntimeHostNotifier

	runtime   Runtime
	consensus consensus.Service

	mu            sync.Mutex
	notifications map[component.ID]*rofl.Notifications

	logger *logging.Logger
}

// NewROFLNotifier creates a new ROFL notifier.
func NewROFLNotifier(runtime Runtime, host *composite.Host, consensus consensus.Service, notifier *RuntimeHostNotifier) *ROFLNotifier {
	logger := logging.GetLogger("runtime/notifier/rofl").
		With("runtime_id", runtime.ID())

	return &ROFLNotifier{
		host:          host,
		notifier:      notifier,
		runtime:       runtime,
		consensus:     consensus,
		notifications: make(map[component.ID]*rofl.Notifications),
		logger:        logger,
	}
}

// Name returns the name of the notifier.
func (n *ROFLNotifier) Name() string {
	return "ROFL notifier"
}

// Serve starts the notifier.
func (n *ROFLNotifier) Serve(ctx context.Context) error {
	n.logger.Info("starting")
	defer n.logger.Info("stopping")

	blkCh, blkSub, err := n.consensus.RootHash().WatchBlocks(ctx, n.runtime.ID())
	if err != nil {
		return fmt.Errorf("failed to subscribe to runtime blocks: %w", err)
	}
	defer blkSub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case blk := <-blkCh:
			n.cleanNotifications()
			n.fetchNotifications()
			n.notifyBlock(blk)
			n.notifyTags(ctx, blk)
		}
	}
}

func (n *ROFLNotifier) notifyBlock(blk *roothash.AnnotatedBlock) {
	for compID := range n.host.Components() {
		n.notifyBlockForComponent(compID, blk)
	}
}

func (n *ROFLNotifier) notifyBlockForComponent(compID component.ID, blk *roothash.AnnotatedBlock) {
	if !n.shouldNotifyBlock(compID) {
		return
	}

	notify := func(ctx context.Context, rr host.RichRuntime) {
		ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
		defer cancel()

		_, err := rr.Call(ctx, &protocol.Body{
			RuntimeNotifyRequest: &protocol.RuntimeNotifyRequest{
				RuntimeBlock: blk,
			},
		})
		if err != nil {
			n.logger.Warn("failed to notify runtime of a new runtime block",
				"err", err,
				"round", blk.Block.Header.Round,
			)
		}
	}

	nf := &Notification{
		comp:   compID,
		queue:  queueROFLBlock,
		notify: notify,
	}

	if err := n.notifier.Queue(nf); err != nil {
		n.logger.Error("failed to queue notification",
			"err", err,
			"component_id", compID,
		)
	}
}

func (n *ROFLNotifier) shouldNotifyBlock(compID component.ID) bool {
	if compID.Kind != component.ROFL {
		return false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	nfs, ok := n.notifications[compID]
	if !ok {
		return false
	}

	return nfs.Blocks
}

func (n *ROFLNotifier) notifyTags(ctx context.Context, blk *roothash.AnnotatedBlock) {
	for compID := range n.host.Components() {
		n.notifyTagsForComponent(ctx, compID, blk)
	}
}

func (n *ROFLNotifier) notifyTagsForComponent(ctx context.Context, compID component.ID, blk *roothash.AnnotatedBlock) {
	events, ok := n.shouldNotifyTags(compID)
	if !ok {
		return
	}

	// Consider optimizing by fetching tags for all components at once.
	tree := transaction.NewTree(n.runtime.Storage(), blk.Block.Header.StorageRootIO())
	defer tree.Close()

	tags, err := tree.GetTagMultiple(ctx, events)
	if err != nil {
		n.logger.Warn("failed to fetch tags for block",
			"err", err,
			"round", blk.Block.Header.Round,
		)
		return
	}

	if len(tags) == 0 {
		return
	}

	tagKeys := make([][]byte, 0, len(tags))
	for _, tag := range tags {
		tagKeys = append(tagKeys, tag.Key)
	}

	notify := func(ctx context.Context, rr host.RichRuntime) {
		ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
		defer cancel()

		_, err := rr.Call(ctx, &protocol.Body{
			RuntimeNotifyRequest: &protocol.RuntimeNotifyRequest{
				RuntimeEvent: &protocol.RuntimeNotifyEvent{
					Block: blk,
					Tags:  tagKeys,
				},
			},
		})
		if err != nil {
			n.logger.Warn("failed to notify runtime of a new event",
				"err", err,
				"round", blk.Block.Header.Round,
			)
		}
	}

	nf := &Notification{
		comp:   compID,
		queue:  queueROFLTags,
		notify: notify,
	}

	if err := n.notifier.Queue(nf); err != nil {
		n.logger.Error("failed to queue notification",
			"err", err,
			"component_id", compID,
		)
	}
}

func (n *ROFLNotifier) shouldNotifyTags(compID component.ID) ([][]byte, bool) {
	if compID.Kind != component.ROFL {
		return nil, false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	nfs, ok := n.notifications[compID]
	if !ok {
		return nil, false
	}

	if len(nfs.Events) == 0 {
		return nil, false
	}

	return nfs.Events, true
}

func (n *ROFLNotifier) cleanNotifications() {
	comps := n.host.Components()

	n.mu.Lock()
	defer n.mu.Unlock()

	for compID := range n.notifications {
		if _, ok := comps[compID]; !ok {
			delete(n.notifications, compID)
		}
	}
}

func (n *ROFLNotifier) fetchNotifications() {
	for compID := range n.host.Components() {
		n.fetchTagsForComponent(compID)
	}
}

func (n *ROFLNotifier) fetchTagsForComponent(compID component.ID) {
	if !n.shouldFetchTags(compID) {
		return
	}

	notify := func(ctx context.Context, rr host.RichRuntime) {
		ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
		defer cancel()

		rsp, err := rr.Call(ctx, &protocol.Body{
			RuntimeQueryRequest: &protocol.RuntimeQueryRequest{
				Method: rofl.MethodGetConfig,
			},
		})
		if err != nil {
			n.logger.Warn("failed to query config",
				"err", err,
			)
			return
		}

		if rsp.RuntimeQueryResponse == nil {
			n.logger.Warn("failed to query config: malformed response")
			return
		}

		var cfg rofl.Config
		if err := cbor.Unmarshal(rsp.RuntimeQueryResponse.Data, &cfg); err != nil {
			n.logger.Error("failed to unmarshal config",
				"err", err,
			)
			return
		}

		n.register(compID, &cfg.Notifications)
	}

	nf := &Notification{
		comp:   compID,
		queue:  queueROFLConfig,
		notify: notify,
	}

	if err := n.notifier.Queue(nf); err != nil {
		n.logger.Error("failed to queue notification",
			"err", err,
			"component_id", compID,
		)
	}
}

func (n *ROFLNotifier) shouldFetchTags(compID component.ID) bool {
	if compID.Kind != component.ROFL {
		return false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.notifications[compID]; ok {
		return false
	}

	return true
}

func (n *ROFLNotifier) register(compID component.ID, nfs *rofl.Notifications) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.notifications[compID] = nfs
}
