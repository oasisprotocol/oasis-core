package p2p

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cenkalti/backoff/v4"
	core "github.com/libp2p/go-libp2p-core"
	pubsub "github.com/libp2p/go-libp2p-pubsub"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

const (
	redispatchMaxWorkers = 10
	redispatchMaxRetries = 5
)

// Handler is a handler for P2P messages.
type Handler interface {
	// AuthenticatePeer handles authenticating a peer that send an
	// incoming message.
	//
	// The message handler will be re-invoked on error with a periodic
	// backoff unless errors are wrapped via `p2pError.Permanent`.
	AuthenticatePeer(peerID signature.PublicKey, msg *Message) error

	// HandlePeerMessage handles an incoming message from a peer.
	//
	// The message handler will be re-invoked on error with a periodic
	// backoff unless errors are wrapped via `p2pError.Permanent`.
	HandlePeerMessage(peerID signature.PublicKey, msg *Message, isOwn bool) error
}

// BaseHandler handler is a P2P handler that can be used in publishing-only
// clients.
type BaseHandler struct {
}

// AuthenticatePeer implements p2p Handler.
func (h *BaseHandler) AuthenticatePeer(peerID signature.PublicKey, msg *Message) error {
	return nil
}

// HandlePeerMessage implements p2p Handler.
func (h *BaseHandler) HandlePeerMessage(peerID signature.PublicKey, msg *Message, isOwn bool) error {
	return nil
}

type topicHandler struct {
	handlersLock sync.RWMutex

	ctx context.Context

	p2p *P2P

	topic       *pubsub.Topic
	cancelRelay pubsub.RelayCancelFunc
	handlers    []Handler

	numWorkers uint64

	logger *logging.Logger
}

type queuedMsg struct {
	peerID core.PeerID
	from   signature.PublicKey
	msg    *Message
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

	var msg Message
	if err = cbor.Unmarshal(envelope.GetData(), &msg); err != nil {
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
		msg:    &msg,
	}

	// If the message will never become valid, do not relay.
	if err = h.dispatchMessage(peerID, m, true); p2pError.IsPermanent(err) {
		return false
	}

	// Note: Messages that may become valid (in-line dispatch
	// failed due to non-permanent error, retry started) will be
	// relayed.
	return true
}

func (h *topicHandler) dispatchMessage(peerID core.PeerID, m *queuedMsg, isInitial bool) error {
	var err error
	defer func() {
		if err == nil || !isInitial {
			return
		}
		if p2pError.IsPermanent(err) {
			h.logger.Error("failed to dispatch message in-line, not retrying",
				"err", err,
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
					"err", err,
					"peer_id", peerID,
				)

				go h.retryWorker(m)

				return
			}
		}
	}()

	h.handlersLock.RLock()
	defer h.handlersLock.RUnlock()

	// Authenticate the peer if it's not us.
	if m.peerID != h.p2p.host.ID() {
		for _, handler := range h.handlers {
			// Perhaps this should reject the message, but it is possible that
			// the local node is just behind.  This does result in stale messages
			// getting retried though.
			if err = handler.AuthenticatePeer(m.from, m.msg); err != nil {
				return err
			}
		}
	}

	h.logger.Debug("handling message", "message", m.msg, "from", m.from)
	for _, handler := range h.handlers {
		// Dispatch the message to the handler.
		// XXX: Could also dispatch the message to all handlers, and only fail after.
		if err = handler.HandlePeerMessage(m.from, m.msg, m.peerID == h.p2p.host.ID()); err != nil {
			h.logger.Error("failed to handle message", "message", m.msg, "from", m.from, "err", err)
			return err
		}
	}

	return nil
}

func (h *topicHandler) retryWorker(m *queuedMsg) {
	defer func() {
		atomic.AddUint64(&h.numWorkers, ^uint64(0))
	}()

	off := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), redispatchMaxRetries)
	bctx := backoff.WithContext(off, h.ctx)

	err := backoff.Retry(func() error {
		derr := h.dispatchMessage(m.peerID, m, false)
		switch derr {
		case nil:
			h.logger.Debug("succeeded in re-dispatching message",
				"peer_id", m.peerID,
			)
		default:
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

func newTopicHandler(p *P2P, runtimeID common.Namespace, handlers []Handler) (string, *topicHandler, error) {
	topicID := runtimeIDToTopicID(runtimeID)
	topic, err := p.pubsub.Join(topicID) // Note: Disallows duplicates.
	if err != nil {
		return "", nil, fmt.Errorf("worker/common/p2p: failed to join topic '%s': %w", topicID, err)
	}

	h := &topicHandler{
		ctx:      p.ctx, // TODO: Should this support individual cancelation?
		p2p:      p,
		topic:    topic,
		handlers: handlers,
		logger:   logging.GetLogger("worker/common/p2p/" + topicID),
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

	return topicID, h, nil
}

func peerIDToPublicKey(peerID core.PeerID) (signature.PublicKey, error) {
	pk, err := peerID.ExtractPublicKey()
	if err != nil {
		return signature.PublicKey{}, err
	}
	return pubKeyToPublicKey(pk)
}
