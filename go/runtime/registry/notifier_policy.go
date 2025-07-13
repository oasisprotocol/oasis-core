package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

const (
	// keyManagerUpdateRetryInterval is the time interval used between failed key manager updates.
	keyManagerUpdateRetryInterval = time.Second
	// maxKeyManagerUpdateRetries is the maximum number of key manager update retries.
	maxKeyManagerUpdateRetries = 16
)

// KeyManagerNotifier notifies compute runtimes about key manager status
// changes and quote policy updates.
type KeyManagerNotifier struct {
	host     *composite.Host
	notifier *RuntimeHostNotifier

	runtime   Runtime
	consensus consensus.Service

	logger *logging.Logger
}

// NewKeyManagerNotifier creates a new key manager notifier.
func NewKeyManagerNotifier(runtime Runtime, host *composite.Host, consensus consensus.Service, notifier *RuntimeHostNotifier) *KeyManagerNotifier {
	logger := logging.GetLogger("runtime/notifier/key_manager").
		With("runtime_id", runtime.ID())

	return &KeyManagerNotifier{
		host:      host,
		notifier:  notifier,
		runtime:   runtime,
		consensus: consensus,
		logger:    logger,
	}
}

// Name returns the name of the notifier.
func (n *KeyManagerNotifier) Name() string {
	return "key manager notifier"
}

// Serve starts the notifier.
func (n *KeyManagerNotifier) Serve(ctx context.Context) error {
	n.logger.Info("starting")
	defer n.logger.Info("stopping")

	kmRtID, ok, err := n.discoverKeyManager(ctx)
	if err != nil {
		n.logger.Error("failed to discover key manager",
			"err", err,
		)
		return fmt.Errorf("failed to discover key manager: %w", err)
	}

	if !ok {
		n.logger.Info("skipping watching policy updates")
		return nil
	}

	if err := n.watchKmPolicyUpdates(ctx, kmRtID); err != nil {
		n.logger.Error("failed to watch key manager policy updates",
			"err", err,
		)
		return fmt.Errorf("failed to watch key manager policy updates: %w", err)
	}

	return nil
}

func (n *KeyManagerNotifier) discoverKeyManager(ctx context.Context) (*common.Namespace, bool, error) {
	n.logger.Info("discovering key manager", "runtime_id", n.runtime.ID())

	// Subscribe to runtime descriptor updates.
	dscCh, dscSub, err := n.runtime.WatchRegistryDescriptor()
	if err != nil {
		return nil, false, fmt.Errorf("failed to subscribe to registry descriptor updates: %w", err)
	}
	defer dscSub.Close()

	// Obtain the current runtime descriptor.
	rtDsc, err := n.runtime.RegistryDescriptor(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get registry descriptor: %w", err)
	}

	// Only proceed with key manager policy updates for compute runtimes.
	if rtDsc.Kind != registry.KindCompute {
		return nil, false, nil
	}

	// Wait for the runtime to choose the key manager.
	for {
		n.logger.Debug("registry descriptor updated",
			"key_manager", rtDsc.KeyManager,
		)

		if rtDsc.KeyManager != nil {
			return rtDsc.KeyManager, true, nil
		}

		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case rtDsc = <-dscCh:
		}
	}
}

func (n *KeyManagerNotifier) watchKmPolicyUpdates(ctx context.Context, kmRtID *common.Namespace) error {
	n.logger.Debug("watching key manager policy updates", "keymanager", kmRtID)

	// Subscribe to key manager status updates (policy might change).
	stCh, stSub, err := n.consensus.KeyManager().Secrets().WatchStatuses(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch key manager secrets statuses: %w", err)
	}
	defer stSub.Close()

	// Subscribe to epoch transitions (quote policy might change).
	epoCh, sub, err := n.consensus.Beacon().WatchEpochs(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch epochs: %w", err)
	}
	defer sub.Close()

	// Subscribe to runtime host events (policies will be lost on restarts).
	evCh, evSub := n.host.WatchEvents()
	defer evSub.Close()

	var (
		statusUpdated      = true
		quotePolicyUpdated = true
	)

	var (
		st *secrets.Status
		sc *node.SGXConstraints
		vi *registry.VersionInfo
	)

	for {
		// Make sure that we actually have a new status.
		if !statusUpdated && st != nil {
			n.updateKeyManagerStatus(st)
			statusUpdated = true
		}

		// Make sure that we actually have a new quote policy and that the current runtime version
		// supports quote policy updates.
		if !quotePolicyUpdated && sc != nil && sc.Policy != nil {
			n.updateKeyManagerQuotePolicy(sc.Policy)
			quotePolicyUpdated = true
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case newSt := <-stCh:
			// Ignore status updates for a different key manager.
			if !newSt.ID.Equal(kmRtID) {
				continue
			}
			st = newSt

			statusUpdated = false
		case epoch := <-epoCh:
			// Check if the key manager was redeployed, as that is when a new quote policy might
			// take effect.
			dsc, err := n.consensus.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
				Height: consensus.HeightLatest,
				ID:     *kmRtID,
			})
			if err != nil {
				n.logger.Error("failed to query key manager runtime descriptor",
					"err", err,
				)
				continue
			}

			// Quote polices can only be set on SGX hardwares.
			if dsc.TEEHardware != node.TEEHardwareIntelSGX {
				continue
			}

			// No need to update the policy if the key manager is sill running the same version.
			newVi := dsc.ActiveDeployment(epoch)
			if newVi.Equal(vi) {
				continue
			}
			vi = newVi

			// Parse SGX constraints.
			var newSc node.SGXConstraints
			if err := cbor.Unmarshal(vi.TEE, &newSc); err != nil {
				n.logger.Error("malformed SGX constraints",
					"err", err,
				)
				continue
			}
			sc = &newSc

			quotePolicyUpdated = false
		case ev := <-evCh:
			// Runtime host changes, make sure to update the policies if runtime is restarted.
			if ev.Started == nil && ev.Updated == nil {
				continue
			}

			statusUpdated = false
			quotePolicyUpdated = false
		}
	}
}

func (n *KeyManagerNotifier) updateKeyManagerStatus(status *secrets.Status) {
	n.logger.Debug("got key manager status update", "status", status)

	for compID := range n.host.Components() {
		n.updateKeyManagerStatusForComponent(compID, status)
	}
}

func (n *KeyManagerNotifier) updateKeyManagerStatusForComponent(compID component.ID, status *secrets.Status) {
	notify := func(ctx context.Context, rr host.RichRuntime) {
		req := &protocol.Body{
			RuntimeKeyManagerStatusUpdateRequest: &protocol.RuntimeKeyManagerStatusUpdateRequest{
				Status: *status,
			},
		}

		for range maxKeyManagerUpdateRetries {
			callCtx, cancelFn := context.WithTimeout(ctx, notifyTimeout)
			_, err := rr.Call(callCtx, req)
			cancelFn()

			if err != nil {
				n.logger.Error("failed dispatching key manager status update to runtime",
					"err", err,
				)
				select {
				case <-ctx.Done():
				case <-time.After(keyManagerUpdateRetryInterval):
					continue
				}
			}
			break
		}
	}

	nf := &Notification{
		comp:   compID,
		queue:  queueKeyManagerStatus,
		notify: notify,
	}

	if err := n.notifier.Queue(nf); err != nil {
		n.logger.Error("failed to queue notification",
			"component_id", nf.comp,
			"queue", nf.queue,
			"err", err,
		)
	}
}

func (n *KeyManagerNotifier) updateKeyManagerQuotePolicy(policy *quote.Policy) {
	n.logger.Debug("got key manager quote policy update", "policy", policy)

	for compID := range n.host.Components() {
		n.updateKeyManagerQuotePolicyForComponent(compID, policy)
	}
}

func (n *KeyManagerNotifier) updateKeyManagerQuotePolicyForComponent(compID component.ID, policy *quote.Policy) {
	notify := func(ctx context.Context, rr host.RichRuntime) {
		req := &protocol.Body{
			RuntimeKeyManagerQuotePolicyUpdateRequest: &protocol.RuntimeKeyManagerQuotePolicyUpdateRequest{
				Policy: *policy,
			},
		}

		for range maxKeyManagerUpdateRetries {
			callCtx, cancelFn := context.WithTimeout(ctx, notifyTimeout)
			_, err := rr.Call(callCtx, req)
			cancelFn()

			if err != nil {
				n.logger.Error("failed dispatching key manager quote policy update to runtime",
					"err", err,
				)
				select {
				case <-ctx.Done():
				case <-time.After(keyManagerUpdateRetryInterval):
					continue
				}
			}
			break
		}
	}

	nf := &Notification{
		comp:   compID,
		queue:  queueKeyManagerQuotePolicy,
		notify: notify,
	}

	if err := n.notifier.Queue(nf); err != nil {
		n.logger.Error("failed to queue notification",
			"component_id", nf.comp,
			"queue", nf.queue,
			"err", err,
		)
	}
}
