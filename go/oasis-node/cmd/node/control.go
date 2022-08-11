package node

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	keymanagerWorker "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

var (
	_ control.ControlledNode = (*Node)(nil)
	_ registration.Delegate  = (*Node)(nil)
)

// RegistrationStopped implements registration.Delegate.
func (n *Node) RegistrationStopped() {
	n.Stop()
}

// RequestShutdown implements control.ControlledNode.
func (n *Node) RequestShutdown() (<-chan struct{}, error) {
	if n.RegistrationWorker == nil {
		// In case there is no registration worker, we can just trigger an immediate shutdown.
		ch := make(chan struct{})
		go func() {
			close(ch)
			n.RegistrationStopped()
		}()
		return ch, nil
	}

	if err := n.RegistrationWorker.RequestDeregistration(); err != nil {
		return nil, err
	}
	// This returns only the registration worker's event channel,
	// otherwise the caller (usually the control grpc server) will only
	// get notified once everything is already torn down - perhaps
	// including the server.
	return n.RegistrationWorker.Quit(), nil
}

// Ready implements control.ControlledNode.
func (n *Node) Ready() <-chan struct{} {
	return n.readyCh
}

// GetIdentity implements control.ControlledNode.
func (n *Node) GetIdentity() *identity.Identity {
	return n.Identity
}

// GetRegistrationStatus implements control.ControlledNode.
func (n *Node) GetRegistrationStatus(ctx context.Context) (*control.RegistrationStatus, error) {
	if n.RegistrationWorker == nil {
		return &control.RegistrationStatus{}, nil
	}
	return n.RegistrationWorker.GetRegistrationStatus(ctx)
}

// GetRuntimeStatus implements control.ControlledNode.
func (n *Node) GetRuntimeStatus(ctx context.Context) (map[common.Namespace]control.RuntimeStatus, error) {
	runtimes := make(map[common.Namespace]control.RuntimeStatus)

	// Seed node doesn't have a runtime registry.
	if n.RuntimeRegistry == nil {
		return runtimes, nil
	}

	for _, rt := range n.RuntimeRegistry.Runtimes() {
		var status control.RuntimeStatus

		// Fetch runtime registry descriptor. Do not wait too long for the descriptor to become
		// available as otherwise we may be blocked until the node is synced.
		dscCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		dsc, err := rt.ActiveDescriptor(dscCtx)
		cancel()
		switch err {
		case nil:
			status.Descriptor = dsc
		case context.DeadlineExceeded:
			// The descriptor may not yet be available. It is fine if we use nil in this case.
		default:
			n.logger.Error("failed to fetch registry descriptor",
				"err", err,
				"runtime_id", rt.ID(),
			)
		}

		// Fetch latest block as seen by this node.
		blk, err := n.Consensus.RootHash().GetLatestBlock(ctx, &roothash.RuntimeRequest{
			RuntimeID: rt.ID(),
			Height:    consensus.HeightLatest,
		})
		switch err {
		case nil:
			status.LatestRound = blk.Header.Round
			status.LatestHash = blk.Header.EncodedHash()
			status.LatestTime = blk.Header.Timestamp
			status.LatestStateRoot = storage.Root{
				Namespace: blk.Header.Namespace,
				Version:   blk.Header.Round,
				Type:      storage.RootTypeState,
				Hash:      blk.Header.StateRoot,
			}
		default:
			n.logger.Error("failed to fetch latest runtime block",
				"err", err,
				"runtime_id", rt.ID(),
			)
		}

		// Fetch latest genesis block as seen by this node.
		blk, err = n.Consensus.RootHash().GetGenesisBlock(ctx, &roothash.RuntimeRequest{
			RuntimeID: rt.ID(),
			Height:    consensus.HeightLatest,
		})
		switch err {
		case nil:
			status.GenesisRound = blk.Header.Round
			status.GenesisHash = blk.Header.EncodedHash()
		default:
			n.logger.Error("failed to fetch genesis runtime block",
				"err", err,
				"runtime_id", rt.ID(),
			)
		}

		// Fetch the oldest retained block.
		blk, err = rt.History().GetEarliestBlock(ctx)
		switch err {
		case nil:
			status.LastRetainedRound = blk.Header.Round
			status.LastRetainedHash = blk.Header.EncodedHash()
		default:
			n.logger.Error("failed to fetch last retained runtime block",
				"err", err,
				"runtime_id", rt.ID(),
			)
		}

		// Fetch common committee worker status.
		if rtNode := n.CommonWorker.GetRuntime(rt.ID()); rtNode != nil {
			status.Committee, err = rtNode.GetStatus(ctx)
			if err != nil {
				n.logger.Error("failed to fetch common committee worker status",
					"err", err,
					"runtime_id", rt.ID(),
				)
			}
		}

		// Fetch executor worker status.
		if execNode := n.ExecutorWorker.GetRuntime(rt.ID()); execNode != nil {
			status.Executor, err = execNode.GetStatus(ctx)
			if err != nil {
				n.logger.Error("failed to fetch executor worker status",
					"err", err,
					"runtime_id", rt.ID(),
				)
			}
		}

		// Fetch storage worker status.
		if storageNode := n.StorageWorker.GetRuntime(rt.ID()); storageNode != nil {
			status.Storage, err = storageNode.GetStatus(ctx)
			if err != nil {
				n.logger.Error("failed to fetch storage worker status",
					"err", err,
					"runtime_id", rt.ID(),
				)
			}
		}

		runtimes[rt.ID()] = status
	}
	return runtimes, nil
}

// GetKeymanagerStatus implements control.ControlledNode.
func (n *Node) GetKeymanagerStatus(ctx context.Context) (*keymanagerWorker.Status, error) {
	if n.KeymanagerWorker == nil || !n.KeymanagerWorker.Enabled() {
		return nil, nil
	}
	return n.KeymanagerWorker.GetStatus(ctx)
}

// GetPendingUpgrades implements control.ControlledNode.
func (n *Node) GetPendingUpgrades(ctx context.Context) ([]*upgrade.PendingUpgrade, error) {
	return n.Upgrader.PendingUpgrades(ctx)
}
