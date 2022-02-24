package runtime

import (
	"bytes"
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// KeymanagerReplicate is the keymanager replication scenario.
var KeymanagerReplicate scenario.Scenario = newKmReplicateImpl()

type kmReplicateImpl struct {
	runtimeImpl
}

func newKmReplicateImpl() scenario.Scenario {
	return &kmReplicateImpl{
		runtimeImpl: *newRuntimeImpl("keymanager-replication", BasicKVEncTestClient),
	}
}

func (sc *kmReplicateImpl) Clone() scenario.Scenario {
	return &kmReplicateImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *kmReplicateImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// This requires multiple keymanagers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1},
		{Runtime: 0, Entity: 1},
	}

	return f, nil
}

func (sc *kmReplicateImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err := sc.waitTestClientOnly(); err != nil {
		return err
	}

	// Open a control connection to the replica.
	if kmLen := len(sc.Net.Keymanagers()); kmLen < 2 {
		return fmt.Errorf("expected more than 1 keymanager, have: %v", kmLen)
	}
	replica := sc.Net.Keymanagers()[1]

	ctrl, err := oasis.NewController(replica.SocketPath())
	if err != nil {
		return err
	}

	// Extract the replica's ExtraInfo.
	node, err := ctrl.Registry.GetNode(
		ctx,
		&registry.IDQuery{
			ID: replica.NodeID,
		},
	)
	if err != nil {
		return err
	}
	rt := node.GetRuntime(keymanagerID, version.Version{})
	if rt == nil {
		return fmt.Errorf("replica is missing keymanager runtime from descriptor")
	}
	var signedInitResponse keymanager.SignedInitResponse
	if err = cbor.Unmarshal(rt.ExtraInfo, &signedInitResponse); err != nil {
		return fmt.Errorf("failed to unmarshal replica extrainfo")
	}

	// Grab a state dump and cross check the checksum with that of
	// the replica.
	doc, err := ctrl.Consensus.StateToGenesis(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to obtain consensus state: %w", err)
	}
	if err = func() error {
		for _, status := range doc.KeyManager.Statuses {
			if !status.ID.Equal(&keymanagerID) {
				continue
			}
			if !status.IsInitialized {
				return fmt.Errorf("key manager failed to initialize")
			}
			if !bytes.Equal(status.Checksum, signedInitResponse.InitResponse.Checksum) {
				return fmt.Errorf("key manager failed to replicate, checksum mismatch")
			}
			return nil
		}
		return fmt.Errorf("consensus state missing km status")
	}(); err != nil {
		return err
	}

	// Since the replica has published an ExtraInfo that shows that it has
	// the correct master secret checksum, the replication process has
	// succeeded from the enclave's point of view.

	// Query the node's keymanager consensus endpoint.
	status, err := ctrl.Keymanager.GetStatus(ctx, &registry.NamespaceQuery{
		ID: keymanagerID,
	})
	if err != nil {
		return err
	}
	for _, v := range status.Nodes {
		// And ensure that the node is present.
		if v.Equal(replica.NodeID) {
			return nil
		}
	}

	return fmt.Errorf("node missing from km status")
}
