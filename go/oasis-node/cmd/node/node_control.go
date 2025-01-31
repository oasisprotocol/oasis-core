package node

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	keymanagerWorker "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
)

// Assert that the node implements NodeController interface.
var _ control.NodeController = (*Node)(nil)

// RequestShutdown implements control.NodeController.
func (n *Node) RequestShutdown(ctx context.Context, wait bool) error {
	ch, err := n.requestShutdown()
	if err != nil {
		return err
	}
	if wait {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (n *Node) requestShutdown() (<-chan struct{}, error) {
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

// WaitReady implements control.NodeController.
func (n *Node) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.readyCh:
		return nil
	}
}

// IsReady implements control.NodeController.
func (n *Node) IsReady(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-n.readyCh:
		return true, nil
	default:
		return false, nil
	}
}

// WaitSync implements control.NodeController.
func (n *Node) WaitSync(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.Consensus.Synced():
		return nil
	}
}

// IsSynced implements control.NodeController.
func (n *Node) IsSynced(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-n.Consensus.Synced():
		return true, nil
	default:
		return false, nil
	}
}

// UpgradeBinary implements control.NodeController.
func (n *Node) UpgradeBinary(_ context.Context, descriptor *upgrade.Descriptor) error {
	return n.Upgrader.SubmitDescriptor(descriptor)
}

// CancelUpgrade implements control.NodeController.
func (n *Node) CancelUpgrade(_ context.Context, descriptor *upgrade.Descriptor) error {
	return n.Upgrader.CancelUpgrade(descriptor)
}

// GetStatus implements control.NodeController.
func (n *Node) GetStatus(ctx context.Context) (*control.Status, error) {
	cs, err := n.getConsensusStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get consensus status: %w", err)
	}

	lcs, err := n.getLightClientStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get light client status: %w", err)
	}

	rs, err := n.getRegistrationStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get registration status: %w", err)
	}

	runtimes, err := n.getRuntimeStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime status: %w", err)
	}

	kms, err := n.getKeymanagerStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get key manager worker status: %w", err)
	}

	pendingUpgrades, err := n.getPendingUpgrades()
	if err != nil {
		return nil, fmt.Errorf("failed to get pending upgrades: %w", err)
	}

	ident := n.getIdentityStatus()

	p2p := n.getP2PStatus()

	var ds *control.DebugStatus
	if debugEnabled := cmdFlags.DebugDontBlameOasis(); debugEnabled {
		ds = &control.DebugStatus{
			Enabled:   debugEnabled,
			AllowRoot: cmdFlags.DebugAllowRoot(),
		}
	}

	return &control.Status{
		SoftwareVersion: version.SoftwareVersion,
		Mode:            config.GlobalConfig.Mode,
		Debug:           ds,
		Identity:        ident,
		Consensus:       cs,
		LightClient:     lcs,
		Runtimes:        runtimes,
		Keymanager:      kms,
		Registration:    rs,
		PendingUpgrades: pendingUpgrades,
		P2P:             p2p,
	}, nil
}

// AddBundle implements control.NodeController.
func (n *Node) AddBundle(_ context.Context, path string) error {
	return n.RuntimeRegistry.GetBundleManager().Add(path)
}

func (n *Node) getIdentityStatus() control.IdentityStatus {
	return control.IdentityStatus{
		Node:      n.Identity.NodeSigner.Public(),
		Consensus: n.Identity.ConsensusSigner.Public(),
		TLS:       n.Identity.TLSSigner.Public(),
	}
}

func (n *Node) getConsensusStatus(ctx context.Context) (*consensus.Status, error) {
	return n.Consensus.GetStatus(ctx)
}

func (n *Node) getLightClientStatus() (*consensus.LightClientStatus, error) {
	return n.LightClient.GetStatus()
}

func (n *Node) getRegistrationStatus(ctx context.Context) (*control.RegistrationStatus, error) {
	if n.RegistrationWorker == nil {
		return &control.RegistrationStatus{}, nil
	}
	return n.RegistrationWorker.GetRegistrationStatus(ctx)
}

func (n *Node) getRuntimeStatus(ctx context.Context) (map[common.Namespace]control.RuntimeStatus, error) {
	runtimes := make(map[common.Namespace]control.RuntimeStatus)

	for _, rt := range n.RuntimeRegistry.Runtimes() {
		if !rt.IsManaged() {
			continue
		}

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

		// Take storage into account for last retained round.
		if config.GlobalConfig.Mode.HasLocalStorage() {
			lsb, ok := rt.Storage().(storage.LocalBackend)
			switch ok {
			case false:
				n.logger.Error("local storage backend expected",
					"runtime_id", rt.ID(),
				)
			default:
				// Update last retained round if storage earliest round is higher.
				if earliest := lsb.NodeDB().GetEarliestVersion(); earliest > status.LastRetainedRound {
					blk, err = rt.History().GetBlock(ctx, earliest)
					switch err {
					case nil:
						status.LastRetainedRound = blk.Header.Round
						status.LastRetainedHash = blk.Header.EncodedHash()
					default:
						n.logger.Error("failed to fetch runtime block",
							"err", err,
							"round", earliest,
							"runtime_id", rt.ID(),
						)
					}

				}

			}
		}

		// Fetch common committee worker status.
		if rtNode := n.CommonWorker.GetRuntime(rt.ID()); rtNode != nil {
			status.Committee, err = rtNode.GetStatus()
			if err != nil {
				n.logger.Error("failed to fetch common committee worker status",
					"err", err,
					"runtime_id", rt.ID(),
				)
			}
		}

		// Fetch executor worker status.
		if execNode := n.ExecutorWorker.GetRuntime(rt.ID()); execNode != nil {
			status.Executor, err = execNode.GetStatus()
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

		// Fetch provisioner type.
		status.Provisioner = "none"
		if provisioner := rt.HostProvisioner(); provisioner != nil {
			status.Provisioner = provisioner.Name()
		}

		// Fetch the status of all components associated with the runtime.
		for _, comp := range n.RuntimeRegistry.GetBundleRegistry().Components(rt.ID()) {
			status.Components = append(status.Components, control.ComponentStatus{
				Kind:     comp.Kind,
				Name:     comp.Name,
				Version:  comp.Version,
				Detached: comp.Detached,
				Disabled: comp.Disabled,
			})
		}

		// Store the runtime status.
		runtimes[rt.ID()] = status
	}
	return runtimes, nil
}

func (n *Node) getKeymanagerStatus() (*keymanagerWorker.Status, error) {
	if n.KeymanagerWorker == nil || !n.KeymanagerWorker.Enabled() {
		return nil, nil
	}
	return n.KeymanagerWorker.GetStatus()
}

func (n *Node) getPendingUpgrades() ([]*upgrade.PendingUpgrade, error) {
	return n.Upgrader.PendingUpgrades()
}

func (n *Node) getP2PStatus() *p2p.Status {
	return n.P2P.GetStatus()
}
