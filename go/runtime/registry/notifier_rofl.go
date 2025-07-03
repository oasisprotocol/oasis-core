package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmnSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

const (
	// roflAttachRuntimeTimeout is the maximum amount of time runtime attachment can take.
	roflAttachRuntimeTimeout = 2 * time.Second
	// roflNotifyTimeout is the maximum amount of time runtime notification handling can take.
	roflNotifyTimeout = 2 * time.Second
)

type roflAttachRuntimeCmd struct {
	rt host.Runtime
	ch chan<- error
}

type roflEventNotifierCmd struct {
	// registerNotify is the command to register for notifications.
	registerNotify *protocol.HostRegisterNotifyRequest
	// attachRuntime is the command to attach a runtime host.
	attachRuntime *roflAttachRuntimeCmd
}

type roflEventNotifier struct {
	startOne cmnSync.One

	runtime Runtime
	client  runtimeClient.RuntimeClient
	cmdCh   chan *roflEventNotifierCmd

	logger *logging.Logger
}

func newROFLEventNotifier(runtime Runtime, client runtimeClient.RuntimeClient, logger *logging.Logger) *roflEventNotifier {
	return &roflEventNotifier{
		startOne: cmnSync.NewOne(),
		runtime:  runtime,
		client:   client,
		cmdCh:    make(chan *roflEventNotifierCmd),
		logger:   logger,
	}
}

func (en *roflEventNotifier) start() {
	en.startOne.TryStart(en.run)
}

func (en *roflEventNotifier) RegisterNotify(ctx context.Context, rq *protocol.HostRegisterNotifyRequest) error {
	en.start() // Ensure event notifier is running.

	select {
	case <-ctx.Done():
		return ctx.Err()
	case en.cmdCh <- &roflEventNotifierCmd{registerNotify: rq}:
	}
	return nil
}

func (en *roflEventNotifier) AttachRuntime(rt host.Runtime) error {
	en.start() // Ensure event notifier is running.

	ch := make(chan error, 1)
	en.cmdCh <- &roflEventNotifierCmd{attachRuntime: &roflAttachRuntimeCmd{rt, ch}}

	select {
	case <-time.After(roflAttachRuntimeTimeout):
		return fmt.Errorf("timeout while attaching runtime")
	case err := <-ch:
		return err
	}
}

func (en *roflEventNotifier) run(ctx context.Context) {
	var (
		rt    host.Runtime
		blkCh <-chan *roothash.AnnotatedBlock

		notifyBlocks bool
		notifyTags   [][]byte
	)

	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-en.cmdCh:
			// Process a command.
			switch {
			case cmd.registerNotify != nil:
				// Update configuration.
				notifyBlocks = cmd.registerNotify.RuntimeBlock

				if re := cmd.registerNotify.RuntimeEvent; re != nil {
					notifyTags = re.Tags
				} else {
					notifyTags = nil
				}
			case cmd.attachRuntime != nil:
				// Attach runtime.
				var err error
				switch {
				case rt != nil:
					// Already attached.
					err = fmt.Errorf("runtime already attached")
				default:
					// Attach runtime and subscribe to blocks.
					rt = cmd.attachRuntime.rt

					// Subscribe to runtime blocks.
					var blkSub pubsub.ClosableSubscription
					blkCh, blkSub, err = en.client.WatchBlocks(ctx, en.runtime.ID())
					if err != nil {
						err = fmt.Errorf("failed to subscribe to runtime blocks: %w", err)
						break
					}
					defer blkSub.Close()
				}

				cmd.attachRuntime.ch <- err
				close(cmd.attachRuntime.ch)
			default:
				panic("runtime/rofl: unsupported command for event notifier")
			}
		case blk := <-blkCh:
			// New runtime block has been produced.
			if notifyBlocks {
				en.notifyBlock(ctx, rt, blk)
			}

			en.notifyTags(ctx, rt, blk, notifyTags)
		}
	}
}

func (en *roflEventNotifier) notifyBlock(ctx context.Context, rt host.Runtime, blk *roothash.AnnotatedBlock) {
	ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
	defer cancel()

	_, err := rt.Call(ctx, &protocol.Body{
		RuntimeNotifyRequest: &protocol.RuntimeNotifyRequest{
			RuntimeBlock: blk,
		},
	})
	if err != nil {
		en.logger.Warn("failed to deliver block notification to runtime",
			"err", err,
			"round", blk.Block.Header.Round,
		)
	}
}

func (en *roflEventNotifier) notifyTags(
	ctx context.Context,
	rt host.Runtime,
	blk *roothash.AnnotatedBlock,
	notifyTags [][]byte,
) {
	if len(notifyTags) == 0 {
		return
	}

	tree := transaction.NewTree(en.runtime.Storage(), blk.Block.Header.StorageRootIO())
	defer tree.Close()

	tags, err := tree.GetTagMultiple(ctx, notifyTags)
	if err != nil {
		en.logger.Warn("failed to fetch tags for block",
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

	ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
	defer cancel()

	_, err = rt.Call(ctx, &protocol.Body{
		RuntimeNotifyRequest: &protocol.RuntimeNotifyRequest{
			RuntimeEvent: &protocol.RuntimeNotifyEvent{
				Block: blk,
				Tags:  tagKeys,
			},
		},
	})
	if err != nil {
		en.logger.Warn("failed to deliver event notification to runtime",
			"err", err,
			"round", blk.Block.Header.Round,
		)
	}
}
