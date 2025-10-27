package workload

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// NameRegistration is the name of the registration workload.
const NameRegistration = "registration"

// Registration is the registration workload.
var Registration = &registration{
	BaseWorkload: NewBaseWorkload(NameRegistration),
}

const (
	registryNumEntities           = 10
	registryNumNodesPerEntity     = 5
	registryNodeMaxEpochUpdate    = 5
	registryRtOwnerChangeInterval = 20

	registryIterationTimeout = 120 * time.Second
)

type registration struct {
	BaseWorkload

	ns common.Namespace
}

func getRuntime(entityID signature.PublicKey, id common.Namespace, epoch beacon.EpochTime) *registry.Runtime {
	rt := &registry.Runtime{
		Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:        id,
		EntityID:  entityID,
		Kind:      registry.KindCompute,
		Executor: registry.ExecutorParameters{
			GroupSize:    1,
			RoundTimeout: 5,
			MaxMessages:  32,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			BatchFlushTimeout: time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			ProposerTimeout:   2 * time.Second,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
		},
		Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
			scheduler.KindComputeExecutor: {
				scheduler.RoleWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 1,
					},
				},
			},
		},
		GovernanceModel: registry.GovernanceEntity,
		Deployments: []*registry.VersionInfo{
			{
				// Ensure registration will not expire if an epoch transition occurs while creating
				// this descriptor (unless two epoch transitions occur).
				ValidFrom: epoch + 2,
			},
		},
	}
	rt.Genesis.StateRoot.Empty()
	return rt
}

func getNodeDesc(rng *rand.Rand, nodeIdentity *identity.Identity, entityID signature.PublicKey, runtimeID common.Namespace) *node.Node {
	nodeAddr := node.Address{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 12345,
		Zone: "",
	}

	// NOTE: we shouldn't be registering validators, as that would lead to
	// consensus stopping as the registered validators wouldn't actually
	// exist.
	availableRoles := []node.RolesMask{
		node.RoleComputeWorker,
		node.RoleObserver,
	}

	nodeDesc := node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         nodeIdentity.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: 0,
		Roles:      availableRoles[rng.Intn(len(availableRoles))],
		TLS: node.TLSInfo{
			PubKey: nodeIdentity.TLSSigner.Public(),
		},
		P2P: node.P2PInfo{
			ID: nodeIdentity.P2PSigner.Public(),
			Addresses: []node.Address{
				nodeAddr,
			},
		},
		Consensus: node.ConsensusInfo{
			ID: nodeIdentity.ConsensusSigner.Public(),
			Addresses: []node.ConsensusAddress{
				{
					ID:      nodeIdentity.P2PSigner.Public(),
					Address: nodeAddr,
				},
			},
		},
		Runtimes: []*node.Runtime{
			{
				ID: runtimeID,
			},
		},
		VRF: node.VRFInfo{
			ID: nodeIdentity.VRFSigner.Public(),
		},
	}
	return &nodeDesc
}

func signNode(identity *identity.Identity, nodeDesc *node.Node) (*node.MultiSignedNode, error) {
	return node.MultiSignNode(
		[]signature.Signer{
			identity.NodeSigner,
			identity.P2PSigner,
			identity.ConsensusSigner,
			identity.TLSSigner,
			identity.VRFSigner,
		},
		registry.RegisterNodeSignatureContext,
		nodeDesc,
	)
}

// Implements Workload.
func (r *registration) NeedsFunds() bool {
	return true
}

// Implements Workload.
func (r *registration) Run( // nolint: gocyclo
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	consensus consensusAPI.Services,
	sm consensusAPI.SubmissionManager,
	fundingAccount signature.Signer,
	_ []signature.Signer,
) error {
	// Initialize base workload.
	r.BaseWorkload.Init(consensus, sm, fundingAccount)

	beaconClient := beacon.NewClient(conn)
	ctx := context.Background()
	var err error

	// Non-existing runtime.
	if err = r.ns.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000002"); err != nil {
		panic(err)
	}

	nodeIdentitiesDir, err := os.MkdirTemp("", "oasis-e2e-registration")
	if err != nil {
		return fmt.Errorf("txsource/registration: failed to create node-identities dir: %w", err)
	}
	defer os.RemoveAll(nodeIdentitiesDir)

	type runtimeInfo struct {
		entityIdx int
		desc      *registry.Runtime
	}
	rtInfo := &runtimeInfo{}

	// Load all accounts.
	type nodeAcc struct {
		id            *identity.Identity
		nodeDesc      *node.Node
		reckonedNonce uint64
	}
	entityAccs := make([]struct {
		signer         signature.Signer
		address        staking.Address
		reckonedNonce  uint64
		nodeIdentities []*nodeAcc
	}, registryNumEntities)

	fac := memorySigner.NewFactory()
	for i := range entityAccs {
		entityAccs[i].signer, err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
		entityAccs[i].address = staking.NewAddress(entityAccs[i].signer.Public())
	}

	// Register entities.
	// XXX: currently entities are only registered at start. Could also
	// periodically register new entities.
	for i := range entityAccs {
		account, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{
			Height: consensusAPI.HeightLatest,
			Owner:  entityAccs[i].address,
		})
		if err != nil {
			return fmt.Errorf("failed to query account: %w", err)
		}
		entityAccs[i].reckonedNonce = account.General.Nonce

		ent := &entity.Entity{
			Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
			ID:        entityAccs[i].signer.Public(),
		}

		// Generate entity node identities.
		for j := 0; j < registryNumNodesPerEntity; j++ {
			dataDir, err := os.MkdirTemp(nodeIdentitiesDir, "node_")
			if err != nil {
				return fmt.Errorf("failed to create a temporary directory: %w", err)
			}
			ident, err := identity.LoadOrGenerate(dataDir, memorySigner.NewFactory())
			if err != nil {
				return fmt.Errorf("failed generating account node identity: %w", err)
			}
			nodeDesc := getNodeDesc(rng, ident, entityAccs[i].signer.Public(), r.ns)

			nodeAccAddress := staking.NewAddress(ident.NodeSigner.Public())
			account, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{
				Height: consensusAPI.HeightLatest,
				Owner:  nodeAccAddress,
			})
			if err != nil {
				return fmt.Errorf("failed to query account %s: %w", nodeAccAddress, err)
			}
			nodeAccNonce := account.General.Nonce
			entityAccs[i].nodeIdentities = append(entityAccs[i].nodeIdentities, &nodeAcc{ident, nodeDesc, nodeAccNonce})
			ent.Nodes = append(ent.Nodes, ident.NodeSigner.Public())

			// Cleanup temporary node identity directory after generation.
			_ = os.RemoveAll(dataDir)
		}

		// Register entity.
		sigEntity, err := entity.SignEntity(entityAccs[i].signer, registry.RegisterEntitySignatureContext, ent)
		if err != nil {
			return fmt.Errorf("failed to sign entity: %w", err)
		}

		// Submit register entity transaction.
		tx := registry.NewRegisterEntityTx(entityAccs[i].reckonedNonce, nil, sigEntity)
		entityAccs[i].reckonedNonce++
		if err = r.FundSignAndSubmitTx(ctx, entityAccs[i].signer, tx); err != nil {
			r.Logger.Error("failed to sign and submit regsiter entity transaction",
				"tx", tx,
				"signer", entityAccs[i].signer,
			)
			return fmt.Errorf("failed to sign and submit tx: %w", err)
		}

		// Ensure entities have required stake to register runtime.
		if err = r.EscrowFunds(ctx, fundingAccount, entityAccs[i].address, quantity.NewFromUint64(10_000)); err != nil {
			return fmt.Errorf("account escrow failure: %w", err)
		}

		// Register runtime.
		// XXX: currently only a single runtime is used throughout the test, could use more.
		if i == 0 {
			// Current epoch.
			epoch, err := beaconClient.GetEpoch(ctx, consensusAPI.HeightLatest)
			if err != nil {
				return fmt.Errorf("failed to get current epoch: %w", err)
			}

			rtInfo.entityIdx = i
			rtInfo.desc = getRuntime(entityAccs[i].signer.Public(), r.ns, epoch)
			tx := registry.NewRegisterRuntimeTx(entityAccs[i].reckonedNonce, nil, rtInfo.desc)
			entityAccs[i].reckonedNonce++
			if err := r.FundSignAndSubmitTx(ctx, entityAccs[i].signer, tx); err != nil {
				r.Logger.Error("failed to sign and submit register runtime transaction",
					"tx", tx,
					"signer", entityAccs[i].signer,
				)
				return fmt.Errorf("failed to sign and submit tx: %w", err)
			}
		}
	}
	// Cleanup temporary identities directory after generation.
	_ = os.RemoveAll(nodeIdentitiesDir)

	iteration := 0
	var loopCtx context.Context
	var cancel context.CancelFunc
	for {
		if cancel != nil {
			cancel()
		}
		loopCtx, cancel = context.WithTimeout(ctx, registryIterationTimeout)
		defer cancel()

		// Select a random node from random entity and register it.
		selectedEntityIdx := rng.Intn(registryNumEntities)
		selectedAcc := &entityAccs[selectedEntityIdx]
		selectedNode := selectedAcc.nodeIdentities[rng.Intn(registryNumNodesPerEntity)]

		// Current epoch.
		epoch, err := beaconClient.GetEpoch(loopCtx, consensusAPI.HeightLatest)
		if err != nil {
			return fmt.Errorf("failed to get current epoch: %w", err)
		}

		// Randomized expiration.
		// We should update for at minimum 2 epochs, as the epoch could change between querying it
		// and actually performing the registration.
		selectedNode.nodeDesc.Expiration = epoch + 2 + beacon.EpochTime(rng.Intn(registryNodeMaxEpochUpdate-1))
		sigNode, err := signNode(selectedNode.id, selectedNode.nodeDesc)
		if err != nil {
			return fmt.Errorf("failed to sign node: %w", err)
		}

		// Register node.
		tx := registry.NewRegisterNodeTx(selectedNode.reckonedNonce, nil, sigNode)
		selectedNode.reckonedNonce++
		if err := r.FundSignAndSubmitTx(loopCtx, selectedNode.id.NodeSigner, tx); err != nil {
			r.Logger.Error("failed to sign and submit register node transaction",
				"tx", tx,
				"signer", selectedNode.id.NodeSigner,
			)
			return fmt.Errorf("failed to sign and submit tx: %w", err)
		}

		r.Logger.Debug("registered node",
			"node", selectedNode.nodeDesc,
		)

		// Periodically re-register the runtime with a new owner.
		if iteration&registryRtOwnerChangeInterval == 0 {
			// Update runtime owner.
			currentOwner := rtInfo.entityIdx
			rtInfo.desc.EntityID = entityAccs[selectedEntityIdx].signer.Public()
			rtInfo.entityIdx = selectedEntityIdx

			// Sign the transaction with current owner.
			tx := registry.NewRegisterRuntimeTx(entityAccs[currentOwner].reckonedNonce, nil, rtInfo.desc)
			entityAccs[currentOwner].reckonedNonce++

			if err := r.FundSignAndSubmitTx(loopCtx, entityAccs[currentOwner].signer, tx); err != nil {
				r.Logger.Error("failed to sign and submit register runtime transaction",
					"tx", tx,
					"signer", entityAccs[currentOwner].signer,
				)
				return fmt.Errorf("failed to sign and submit tx: %w", err)
			}

			r.Logger.Debug("registered runtime",
				"runtime", rtInfo.desc,
			)
		}

		iteration++
		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			r.Logger.Debug("time's up")
			return nil
		}
	}
}
