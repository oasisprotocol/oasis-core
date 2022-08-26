package p2p

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

const (
	redispatchMaxWorkers = 10
	redispatchMaxRetries = 5
	rawMsgQueueSize      = 50

	// peerMessageProcessTimeout is the maximum time that peer message processing can take.
	peerMessageProcessTimeout = 10 * time.Second
)

type rawMessage struct {
	msg []byte
}

type topicHandler struct {
	ctx context.Context

	p2p *p2p

	topic       *pubsub.Topic
	host        core.Host
	cancelRelay pubsub.RelayCancelFunc
	handler     api.Handler

	numWorkers uint64

	pendingQueue chan *rawMessage

	logger *logging.Logger
}

type queuedMsg struct {
	peerID core.PeerID
	from   signature.PublicKey
	msg    interface{}
}

func (h *topicHandler) topicMessageValidator(ctx context.Context, unused core.PeerID, envelope *pubsub.Message) bool {
	// Tease apart the pubsub message envelope and convert it to
	// the expected format.

	peerID := envelope.GetFrom() // Not ReceivedFrom, could be relayed.
	h.logger.Debug("new message from peer",
		"peer_id", peerID,
		"received_from", envelope.ReceivedFrom,
	)

	id, err := peerIDToPublicKey(peerID)
	if err != nil {
		h.logger.Error("error while extracting public key from peer ID",
			"err", err,
			"peer_id", peerID,
		)
		return false
	}

	var msg interface{}
	if msg, err = h.handler.DecodeMessage(envelope.GetData()); err != nil {
		h.logger.Error("error while parsing message from peer",
			"err", err,
			"peer_id", peerID,
		)
		return false
	}

	// Dispatch the message.  Yes, from the topic validator.  The
	// default topic validator configuration is asynchronous so
	// this won't actually block anything, and it saves having to
	// deserialize the message.
	m := &queuedMsg{
		peerID: peerID,
		from:   id,
		msg:    msg,
	}

	// If the message will never become valid, do not relay.
	if err = h.dispatchMessage(peerID, m, true); !p2pError.ShouldRelay(err) {
		return false
	}

	// Note: Messages that may become valid (in-line dispatch
	// failed due to non-permanent error, retry started) will be
	// relayed.
	return true
}

func (h *topicHandler) dispatchMessage(peerID core.PeerID, m *queuedMsg, isInitial bool) (retErr error) {
	defer func() {
		if retErr == nil || !isInitial {
			return
		}
		if p2pError.IsPermanent(retErr) {
			h.logger.Error("failed to dispatch message in-line, not retrying",
				"err", retErr,
				"peer_id", peerID,
			)
			return
		}

		// Kick off the retry worker if this is the initial attempt to
		// dispatch the message.
		for {
			numWorkers := atomic.LoadUint64(&h.numWorkers)
			if numWorkers > redispatchMaxWorkers {
				h.logger.Error("failed to enqueue message for retry, queue full",
					"peer_id", peerID,
				)
				return
			}
			if atomic.CompareAndSwapUint64(&h.numWorkers, numWorkers, numWorkers+1) {
				h.logger.Error("failed to dispatch message in-line, retrying",
					"err", retErr,
					"peer_id", peerID,
				)

				go h.retryWorker(m)

				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), peerMessageProcessTimeout)
	defer cancel()

	// Run authorization handler if the message is not from us.
	if m.peerID != h.p2p.host.ID() {
		// Perhaps this should reject the message, but it is possible that
		// the local node is just behind.  This does result in stale messages
		// getting retried though.
		if err := h.handler.AuthorizeMessage(ctx, m.from, m.msg); err != nil {
			return err
		}
	}

	h.logger.Debug("handling message", "message", m.msg, "from", m.from)

	// Dispatch the message to the handler.
	if err := h.handler.HandleMessage(ctx, m.from, m.msg, m.peerID == h.p2p.host.ID()); err != nil {
		h.logger.Warn("failed to handle message", "message", m.msg, "from", m.from, "err", err)
		return err
	}

	return nil
}

func (h *topicHandler) retryWorker(m *queuedMsg) {
	defer func() {
		atomic.AddUint64(&h.numWorkers, ^uint64(0))
	}()

	off := backoff.WithMaxRetries(cmnBackoff.NewExponentialBackOff(), redispatchMaxRetries)
	bctx := backoff.WithContext(off, h.ctx)

	err := backoff.Retry(func() error {
		derr := h.dispatchMessage(m.peerID, m, false)
		switch derr {
		case nil:
			h.logger.Debug("succeeded in re-dispatching message",
				"peer_id", m.peerID,
			)
		default:
			derr = p2pError.EnsurePermanent(derr)
			if !p2pError.IsPermanent(derr) {
				h.logger.Warn("failed to-redispatch message, will retry",
					"err", derr,
					"peer_id", m.peerID,
				)
			}
		}
		return derr
	}, bctx)
	if err != nil {
		h.logger.Error("failed to re-dispatch message, not retrying",
			"err", err,
			"peer_id", m.peerID,
		)
	}
}

func (h *topicHandler) tryPublishing(rawMsg []byte) error {
	if len(h.topic.ListPeers()) == 0 {
		// On init, if there are no peers, the library will sometimes just
		// swallow the message and mark it as seen without retrying or returning
		// an error. This special case is to try to preempt that.
		h.logger.Debug("no connected peers, handing off to retry worker")
		select {
		case h.pendingQueue <- &rawMessage{rawMsg}:
			return nil
		default:
			return fmt.Errorf("worker/common/p2p: message queue overflow, libp2p still not initialized")
		}
	}

	return h.topic.Publish(h.ctx, rawMsg)
}

// pendingMessagesWorker handles retrying for P2P messages when there are no connected peers.
func (h *topicHandler) pendingMessagesWorker() {
	mgrInitCh := h.p2p.PeerManager.Initialized()
	for {
		var msg *rawMessage

		select {
		case <-h.ctx.Done():
			return
		case msg = <-h.pendingQueue:
		}

	WaitLoop:
		for mgrInitCh != nil || (len(h.topic.ListPeers()) == 0 && len(h.p2p.PeerManager.KnownPeers()) > 0) {
			select {
			case <-h.ctx.Done():
				return
			case <-mgrInitCh:
				mgrInitCh = nil
				if len(h.p2p.PeerManager.KnownPeers()) == 0 {
					break WaitLoop
				}
			case <-time.After(1 * time.Second):
			}
		}

		if err := h.topic.Publish(h.ctx, msg.msg); err != nil {
			h.logger.Error("failed to publish message to the network",
				"err", err,
			)
		}
	}
}

func newTopicHandler(p *p2p, runtimeID common.Namespace, kind api.TopicKind, handler api.Handler) (string, *topicHandler, error) {
	topicID := p.topicIDForRuntime(runtimeID, kind)
	topic, err := p.pubsub.Join(topicID) // Note: Disallows duplicates.
	if err != nil {
		return "", nil, fmt.Errorf("worker/common/p2p: failed to join topic '%s': %w", topicID, err)
	}

	h := &topicHandler{
		ctx:          p.ctx, // TODO: Should this support individual cancelation?
		p2p:          p,
		topic:        topic,
		host:         p.host,
		handler:      handler,
		pendingQueue: make(chan *rawMessage, rawMsgQueueSize),
		logger:       logging.GetLogger("worker/common/p2p/" + topicID),
	}
	if h.cancelRelay, err = h.topic.Relay(); err != nil {
		// Well, ok, fine.  This should NEVER happen, but try to back out
		// the topic subscription we just did.
		h.logger.Error("failed to enable topic relaying",
			"err", err,
		)
		_ = topic.Close()

		return "", nil, fmt.Errorf("worker/common/p2p: failed to relay topic '%s': %w", topicID, err)
	}

	go h.pendingMessagesWorker()
	return topicID, h, nil
}

func peerIDToPublicKey(peerID core.PeerID) (signature.PublicKey, error) {
	pk, err := peerID.ExtractPublicKey()
	if err != nil {
		return signature.PublicKey{}, err
	}
	return api.PubKeyToPublicKey(pk)
}
