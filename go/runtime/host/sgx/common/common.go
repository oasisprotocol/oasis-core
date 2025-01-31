// Package common implements common SGX functions.
package common

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	sgxQuote "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox"
)

// GetQuotePolicy fetches the quote policy for the given component. In case the policy is
// not available, return the fallback policy.
func GetQuotePolicy(
	ctx context.Context,
	cfg *host.Config,
	cb consensus.Backend,
	fallbackPolicy *sgxQuote.Policy,
) (*sgxQuote.Policy, error) {
	switch cfg.Component.Kind {
	case component.RONL:
		// Load RONL policy from the consensus layer.
		rt, err := cb.Registry().GetRuntime(ctx, &registry.GetRuntimeQuery{
			Height:           consensus.HeightLatest,
			ID:               cfg.ID,
			IncludeSuspended: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to query runtime descriptor: %w", err)
		}
		if d := rt.DeploymentForVersion(cfg.Component.Version); d != nil {
			var sc node.SGXConstraints
			if err = cbor.Unmarshal(d.TEE, &sc); err != nil {
				return nil, fmt.Errorf("malformed runtime SGX constraints: %w", err)
			}

			return sc.Policy, nil
		}
		return fallbackPolicy, nil
	case component.ROFL:
		// Always use fallback policy for ROFL components.
		return fallbackPolicy, nil
	default:
		// No policy.
		return fallbackPolicy, nil
	}
}

// EndorseCapabilityTEE endorses the given CapabilityTEE and submits the signed endorsement to the
// runtime over the given connection.
func EndorseCapabilityTEE(
	ctx context.Context,
	identity *identity.Identity,
	capabilityTEE *node.CapabilityTEE,
	conn protocol.Connection,
	logger *logging.Logger,
) {
	ri, err := conn.GetInfo()
	if err != nil {
		logger.Error("failed to get host information, not endorsing local component",
			"err", err,
		)
		return
	}
	if !ri.Features.EndorsedCapabilityTEE {
		logger.Debug("runtime does not support endorsed TEE capabilities, skipping endorsement")
		return
	}

	// Endorse CapabilityTEE by signing it under the proper domain separation context.
	nodeSignature, err := signature.Sign(
		identity.NodeSigner,
		node.EndorseCapabilityTEESignatureContext,
		cbor.Marshal(capabilityTEE),
	)
	if err != nil {
		logger.Error("failed to sign endorsement of local component",
			"err", err,
		)
		return
	}

	_, err = conn.Call(ctx, &protocol.Body{
		RuntimeCapabilityTEEUpdateEndorsementRequest: &protocol.RuntimeCapabilityTEEUpdateEndorsementRequest{
			EndorsedCapabilityTEE: node.EndorsedCapabilityTEE{
				CapabilityTEE:   *capabilityTEE,
				NodeEndorsement: *nodeSignature,
			},
		},
	})
	if err != nil {
		logger.Error("failed to update endorsement of local component",
			"err", err,
		)
		return
	}

	logger.Debug("successfully updated component's TEE capability endorsement")
}

// UpdateRuntimeQuote sends the given quote bundle to the runtime so it can be configured for remote
// attestation purposes. The runtime responds with a signed attestation.
func UpdateRuntimeQuote(ctx context.Context, conn protocol.Connection, quote *pcs.QuoteBundle) ([]byte, error) {
	// Prepare quote structure.
	q := sgxQuote.Quote{
		PCS: quote,
	}

	// Call the runtime with the quote and TCB bundle.
	rspBody, err := conn.Call(
		ctx,
		&protocol.Body{
			RuntimeCapabilityTEERakQuoteRequest: &protocol.RuntimeCapabilityTEERakQuoteRequest{
				Quote: q,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error while configuring quote: %w", err)
	}
	rsp := rspBody.RuntimeCapabilityTEERakQuoteResponse
	if rsp == nil {
		return nil, fmt.Errorf("unexpected response from runtime")
	}

	return cbor.Marshal(node.SGXAttestation{
		Versioned: cbor.NewVersioned(node.LatestSGXAttestationVersion),
		Quote:     q,
		Height:    rsp.Height,
		Signature: rsp.Signature,
	}), nil
}

// AttestationWorker is the periodic re-attestation worker loop.
//
// It should be started in its own goroutine.
func AttestationWorker(
	interval time.Duration,
	logger *logging.Logger,
	hp *sandbox.HostInitializerParams,
	updateCapabilityFunc func(context.Context, *sandbox.HostInitializerParams) (*node.CapabilityTEE, error),
) {
	t := time.NewTicker(interval)
	defer t.Stop()

	logger = logger.With("runtime_id", hp.Runtime.ID())

	// Get the event emitter.
	eventEmitter, _ := hp.Runtime.(host.RuntimeEventEmitter)

	for {
		select {
		case <-hp.Process.Wait():
			// Process has terminated.
			return
		case <-t.C:
			// Re-attest based on the configured interval.
		case <-hp.NotifyUpdateCapabilityTEE:
			// Re-attest when explicitly requested. Also reset the periodic ticker to make sure we
			// don't needlessly re-attest too often.
			t.Reset(interval)
		}

		// Update CapabilityTEE.
		logger.Info("regenerating CapabilityTEE")

		capabilityTEE, err := updateCapabilityFunc(context.Background(), hp)
		if err != nil {
			logger.Error("failed to regenerate CapabilityTEE",
				"err", err,
			)
			continue
		}

		// Emit event about the updated CapabilityTEE.
		if eventEmitter != nil {
			eventEmitter.EmitEvent(&host.Event{Updated: &host.UpdatedEvent{
				Version:       hp.Version,
				CapabilityTEE: capabilityTEE,
			}})
		}
	}
}
