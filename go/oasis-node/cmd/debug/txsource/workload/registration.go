package workload

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
)

const (
	NameRegistration = "registration"

	registryNumEntities        = 10
	registryNumNodesPerEntity  = 5
	registryNodeMaxEpochUpdate = 5
)

var registryLogger = logging.GetLogger("cmd/txsource/workload/registry")

type registration struct {
	ns common.Namespace
}

func getRuntime(entityID signature.PublicKey, id common.Namespace) *registry.Runtime {
	rt := &registry.Runtime{
		ID:       id,
		EntityID: entityID,
		Kind:     registry.KindCompute,
		Executor: registry.ExecutorParameters{
			GroupSize:    1,
			RoundTimeout: 1 * time.Second,
		},
		Merge: registry.MergeParameters{
			GroupSize:    1,
			RoundTimeout: 1 * time.Second,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			GroupSize:         1,
			Algorithm:         "batching",
			BatchFlushTimeout: 1 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1,
		},
		Storage: registry.StorageParameters{
			GroupSize:               1,
			MaxApplyWriteLogEntries: 100_000,
			MaxApplyOps:             2,
			MaxMergeRoots:           8,
			MaxMergeOps:             2,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
		},
	}
	rt.Genesis.StateRoot.Empty()
	return rt
}

func getNodeDesc(rng *rand.Rand, nodeIdentity *identity.Identity, entityID signature.PublicKey, runtimeID common.Namespace) *node.Node {
	nodeAddr := node.Address{
		TCPAddr: net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 12345,
			Zone: "",
		},
	}

	// NOTE: we shouldn't be registering validators, as that would lead to
	// consensus stopping as the registered validators wouldn't actually
	// exist.
	availableRoles := []node.RolesMask{
		node.RoleStorageWorker,
		node.RoleComputeWorker,
		node.RoleStorageWorker | node.RoleComputeWorker,
	}

	nodeDesc := node.Node{
		ID:         nodeIdentity.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: 0,
		Roles:      availableRoles[rng.Intn(len(availableRoles))],
		Committee: node.CommitteeInfo{
			Certificate: nodeIdentity.TLSCertificate.Certificate[0],
			Addresses: []node.CommitteeAddress{
				{
					Certificate: nodeIdentity.TLSCertificate.Certificate[0],
					Address:     nodeAddr,
				},
			},
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
					ID:      nodeIdentity.ConsensusSigner.Public(),
					Address: nodeAddr,
				},
			},
		},
		Runtimes: []*node.Runtime{
			{
				ID: runtimeID,
			},
		},
	}
	return &nodeDesc
}

func signNode(identity *identity.Identity, nodeDesc *node.Node) (*node.MultiSignedNode, error) {
	nodeSigners := []signature.Signer{
		identity.NodeSigner,
		identity.P2PSigner,
		identity.ConsensusSigner,
		identity.TLSSigner,
	}

	sigNode, err := node.MultiSignNode(nodeSigners, registry.RegisterNodeSignatureContext, nodeDesc)
	if err != nil {
		registryLogger.Error("failed to sign node descriptor",
			"err", err,
		)
		return nil, err
	}

	return sigNode, nil
}

func (r *registration) Run(gracefulExit context.Context, rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, rtc runtimeClient.RuntimeClient) error {
	ctx := context.Background()
	var err error

	if err = r.ns.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000002"); err != nil {
		panic(err)
	}

	baseDir := viper.GetString(cmdCommon.CfgDataDir)
	nodeIdentitiesDir := filepath.Join(baseDir, "node-identities")
	if err = common.Mkdir(nodeIdentitiesDir); err != nil {
		return fmt.Errorf("txsource/registry: failed to create node-identities dir: %w", err)
	}

	// Load all accounts.
	type nodeAcc struct {
		id            *identity.Identity
		nodeDesc      *node.Node
		reckonedNonce uint64
	}
	entityAccs := make([]struct {
		signer         signature.Signer
		reckonedNonce  uint64
		nodeIdentities []*nodeAcc
	}, registryNumEntities)

	fac := memorySigner.NewFactory()
	for i := range entityAccs {
		entityAccs[i].signer, err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
	}

	// Register entities.
	// XXX: currently entities are only registered at start. Could also
	// periodically register new entities.
	for i := range entityAccs {
		entityAccs[i].reckonedNonce, err = cnsc.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
			ID:     entityAccs[i].signer.Public(),
			Height: consensus.HeightLatest,
		})
		if err != nil {
			return fmt.Errorf("GetSignerNonce error: %w", err)
		}

		ent := &entity.Entity{
			ID: entityAccs[i].signer.Public(),
		}

		// Generate entity node identities.
		for j := 0; j < registryNumNodesPerEntity; j++ {
			dataDir, err := ioutil.TempDir(nodeIdentitiesDir, "node_")
			if err != nil {
				return fmt.Errorf("failed to create a temporary directory: %w", err)
			}
			ident, err := identity.LoadOrGenerate(dataDir, memorySigner.NewFactory())
			if err != nil {
				return fmt.Errorf("failed generating account node identity: %w", err)
			}
			nodeDesc := getNodeDesc(rng, ident, entityAccs[i].signer.Public(), r.ns)

			var nodeAccNonce uint64
			nodeAccNonce, err = cnsc.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
				ID:     ident.NodeSigner.Public(),
				Height: consensus.HeightLatest,
			})
			if err != nil {
				return fmt.Errorf("GetSignerNonce error: %w", err)
			}

			entityAccs[i].nodeIdentities = append(entityAccs[i].nodeIdentities, &nodeAcc{ident, nodeDesc, nodeAccNonce})
			ent.Nodes = append(ent.Nodes, ident.NodeSigner.Public())
		}

		// Register entity.
		sigEntity, err := entity.SignEntity(entityAccs[i].signer, registry.RegisterEntitySignatureContext, ent)
		if err != nil {
			return fmt.Errorf("failed to sign entity: %w", err)
		}

		// Estimate gas and submit transaction.
		tx := registry.NewRegisterEntityTx(entityAccs[i].reckonedNonce, &transaction.Fee{}, sigEntity)
		entityAccs[i].reckonedNonce++
		gas, err := cnsc.EstimateGas(ctx, &consensus.EstimateGasRequest{
			Caller:      entityAccs[i].signer.Public(),
			Transaction: tx,
		})
		if err != nil {
			return fmt.Errorf("failed to estimate gas: %w", err)
		}
		tx.Fee.Gas = gas

		signedTx, err := transaction.Sign(entityAccs[i].signer, tx)
		if err != nil {
			return fmt.Errorf("transaction.Sign: %w", err)
		}
		if err = cnsc.SubmitTx(ctx, signedTx); err != nil {
			return fmt.Errorf("cnsc.SubmitTx: %w", err)
		}

		// Register runtime.
		// XXX: currently only a single runtime is registered at start. Could
		// also periodically register new runtimes.
		if i == 0 {
			runtimeDesc := getRuntime(entityAccs[i].signer.Public(), r.ns)
			sigRuntime, err := registry.SignRuntime(entityAccs[i].signer, registry.RegisterRuntimeSignatureContext, runtimeDesc)
			if err != nil {
				return fmt.Errorf("failed to sign entity: %w", err)
			}

			tx := registry.NewRegisterRuntimeTx(entityAccs[i].reckonedNonce, &transaction.Fee{}, sigRuntime)
			gas, err := cnsc.EstimateGas(ctx, &consensus.EstimateGasRequest{
				Caller:      entityAccs[i].signer.Public(),
				Transaction: tx,
			})
			if err != nil {
				return fmt.Errorf("failed to estimate gas: %w", err)
			}
			tx.Fee.Gas = gas
			entityAccs[i].reckonedNonce++

			signedTx, err := transaction.Sign(entityAccs[i].signer, tx)
			if err != nil {
				return fmt.Errorf("transaction.Sign: %w", err)
			}
			if err = cnsc.SubmitTx(ctx, signedTx); err != nil {
				return fmt.Errorf("cnsc.SubmitTx: %w", err)
			}
		}
	}

	for {
		// Select a random node from random entity and register it.
		selectedAcc := &entityAccs[rng.Intn(registryNumEntities)]
		selectedNode := selectedAcc.nodeIdentities[rng.Intn(registryNumNodesPerEntity)]

		// Current epoch.
		epoch, err := cnsc.GetEpoch(ctx, consensus.HeightLatest)
		if err != nil {
			return fmt.Errorf("GetEpoch: %w", err)
		}

		// Randomized expiration.
		// We should update for at minimum 2 epochs, as the epoch could change between querying it
		// and actually performing the registration.
		selectedNode.nodeDesc.Expiration = uint64(epoch) + 2 + uint64(rng.Intn(registryNodeMaxEpochUpdate-1))
		sigNode, err := signNode(selectedNode.id, selectedNode.nodeDesc)
		if err != nil {
			return fmt.Errorf("signNode: %w", err)
		}

		// Register node.
		tx := registry.NewRegisterNodeTx(selectedNode.reckonedNonce, &transaction.Fee{}, sigNode)
		gas, err := cnsc.EstimateGas(ctx, &consensus.EstimateGasRequest{
			Caller:      selectedNode.id.NodeSigner.Public(),
			Transaction: tx,
		})
		if err != nil {
			return fmt.Errorf("failed to estimate gas: %w", err)
		}
		tx.Fee.Gas = gas

		selectedNode.reckonedNonce++

		signedTx, err := transaction.Sign(selectedNode.id.NodeSigner, tx)
		if err != nil {
			return fmt.Errorf("transaction.Sign: %w", err)
		}
		transferLogger.Debug("submitting registration",
			"node", selectedNode.nodeDesc,
		)
		if err = cnsc.SubmitTx(ctx, signedTx); err != nil {
			return fmt.Errorf("cnsc.SubmitTx: %w", err)
		}
		transferLogger.Debug("registered node",
			"node", selectedNode.nodeDesc,
		)

		select {
		case <-gracefulExit.Done():
			transferLogger.Debug("time's up")
			return nil
		default:
		}
	}
}
