// +build gofuzz

package fuzz2

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/fill2"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func mustInitPublicKey(t *testing.T, hex string) (pk signature.PublicKey) {
	require.NoError(t, pk.UnmarshalHex(hex), "UnmarshalHex %s", hex)
	return
}

func mustInitQuantity(t *testing.T, i int64) (q quantity.Quantity) {
	require.NoError(t, q.FromInt64(i), "FromInt64 %d", i)
	return
}

func mustInitAddress(t *testing.T, addr string) (a node.Address) {
	require.NoError(t, a.UnmarshalText([]byte(addr)), "UnmarshalText %s", addr)
	return
}

func mustGenerateCert(t *testing.T) (signature.PublicKey, *tls.Certificate) {
	cert, err := tlsCert.Generate(identity.CommonName)
	require.NoError(t, err, "tlsCert Generate")
	return memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey)).Public(), cert
}

func marshalAndCheck(t *testing.T, v interface{}, msg string) []byte {
	data := fill2.Marshal(v)
	fmt.Printf("data [%x]\n", data)
	v2r := reflect.New(reflect.TypeOf(v).Elem())
	reflect.ValueOf(fill2.Unmarshal).Call([]reflect.Value{reflect.ValueOf(data), v2r})
	v2 := v2r.Interface()
	require.Equal(t, v, v2, msg)
	return data
}

func fakeSigned(t *testing.T, body interface{}, msg string, signer signature.PublicKey) signature.Signed {
	return signature.Signed{
		Blob: marshalAndCheck(t, body, msg),
		Signature: signature.Signature{
			PublicKey: signer,
			Signature: signature.FakeSignature,
		},
	}
}

func fakeMultiSigned(t *testing.T, body interface{}, msg string, signers ...signature.PublicKey) signature.MultiSigned {
	ms := signature.MultiSigned{
		Blob:       marshalAndCheck(t, body, msg),
		Signatures: make([]signature.Signature, 0, len(signers)),
	}
	for _, pk := range signers {
		ms.Signatures = append(ms.Signatures, signature.Signature{
			PublicKey: pk,
			Signature: signature.FakeSignature,
		})
	}
	return ms
}

func TestFuzz(t *testing.T) {
	require.NoError(t, logging.Initialize(os.Stdout, logging.FmtJSON, logging.LevelDebug, nil), "logging Initialize") // %%%
	var (
		acctRich            = mustInitPublicKey(t, "7200000000000000000000000000000000000000000000000000000000000000")
		entity1             = mustInitPublicKey(t, "3165000000000000000000000000000000000000000000000000000000000000")
		entity2             = mustInitPublicKey(t, "3265000000000000000000000000000000000000000000000000000000000000")
		entity3             = mustInitPublicKey(t, "3365000000000000000000000000000000000000000000000000000000000000")
		node1               = mustInitPublicKey(t, "316e000000000000000000000000000000000000000000000000000000000000")
		node2               = mustInitPublicKey(t, "326e000000000000000000000000000000000000000000000000000000000000")
		node3               = mustInitPublicKey(t, "336e000000000000000000000000000000000000000000000000000000000000")
		node1Com, node1Cert = mustGenerateCert(t)
		node2Com, node2Cert = mustGenerateCert(t)
		node3Com, node3Cert = mustGenerateCert(t)
		node1P2P            = mustInitPublicKey(t, "31706e0000000000000000000000000000000000000000000000000000000000")
		node2P2P            = mustInitPublicKey(t, "32706e0000000000000000000000000000000000000000000000000000000000")
		node3P2P            = mustInitPublicKey(t, "33706e0000000000000000000000000000000000000000000000000000000000")
		node1Cons           = mustInitPublicKey(t, "31636e0000000000000000000000000000000000000000000000000000000000")
		node2Cons           = mustInitPublicKey(t, "32636e0000000000000000000000000000000000000000000000000000000000")
		node3Cons           = mustInitPublicKey(t, "33636e0000000000000000000000000000000000000000000000000000000000")
		node1Addr           = crypto.PublicKeyToTendermint(&node1Cons).Address()
		node2Addr           = crypto.PublicKeyToTendermint(&node2Cons).Address()
		node3Addr           = crypto.PublicKeyToTendermint(&node3Cons).Address()
	)
	nowRich := time.Now()
	now := time.Unix(nowRich.Unix(), int64(nowRich.Nanosecond()))
	doc := genesis.Document{
		Time: now,
		EpochTime: epochtime.Genesis{
			Parameters: epochtime.ConsensusParameters{
				Interval:         2,
				DebugMockBackend: true,
			},
		},
		Registry: registry.Genesis{
			Parameters: registry.ConsensusParameters{
				MaxNodeExpiration: 5,
			},
			Entities: []*entity.SignedEntity{
				{
					fakeSigned(t, &entity.Entity{
						ID:    entity1,
						Nodes: []signature.PublicKey{node1},
					}, "entity1", entity1),
				},
				{
					fakeSigned(t, &entity.Entity{
						ID:    entity2,
						Nodes: []signature.PublicKey{node2},
					}, "entity2", entity2),
				},
				{
					fakeSigned(t, &entity.Entity{
						ID:    entity3,
						Nodes: []signature.PublicKey{node3},
					}, "entity3", entity3),
				},
			},
			Nodes: []*node.MultiSignedNode{
				{
					fakeMultiSigned(t, &node.Node{
						ID:       node1,
						EntityID: entity1,
						Committee: node.CommitteeInfo{
							Certificate: node1Cert.Certificate[0],
						},
						P2P: node.P2PInfo{
							ID: node1P2P,
						},
						Consensus: node.ConsensusInfo{
							ID: node1Cons,
							Addresses: []node.ConsensusAddress{
								{
									Address: mustInitAddress(t, "1.0.0.1:26656"),
								},
							},
						},
						Roles: node.RoleValidator,
					}, "node1", node1, node1P2P, node1Cons, node1Com),
				},
				{
					fakeMultiSigned(t, &node.Node{
						ID:       node2,
						EntityID: entity2,
						Committee: node.CommitteeInfo{
							Certificate: node2Cert.Certificate[0],
						},
						P2P: node.P2PInfo{
							ID: node2P2P,
						},
						Consensus: node.ConsensusInfo{
							ID: node2Cons,
							Addresses: []node.ConsensusAddress{
								{
									Address: mustInitAddress(t, "1.0.0.2:26656"),
								},
							},
						},
						Roles: node.RoleValidator,
					}, "node2", node2, node2P2P, node2Cons, node2Com),
				},
				{
					fakeMultiSigned(t, &node.Node{
						ID:       node3,
						EntityID: entity3,
						Committee: node.CommitteeInfo{
							Certificate: node3Cert.Certificate[0],
						},
						P2P: node.P2PInfo{
							ID: node3P2P,
						},
						Consensus: node.ConsensusInfo{
							ID: node3Cons,
							Addresses: []node.ConsensusAddress{
								{
									Address: mustInitAddress(t, "1.0.0.3:26656"),
								},
							},
						},
						Roles: node.RoleValidator,
					}, "node3", node3, node3P2P, node3Cons, node3Com),
				},
			},
			NodeStatuses: map[signature.PublicKey]*registry.NodeStatus{},
		},
		Staking: staking.Genesis{
			Parameters: staking.ConsensusParameters{
				Thresholds: map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            mustInitQuantity(t, 1000),
					staking.KindNodeValidator:     mustInitQuantity(t, 1000),
					staking.KindNodeCompute:       mustInitQuantity(t, 1000),
					staking.KindNodeStorage:       mustInitQuantity(t, 1000),
					staking.KindNodeKeyManager:    mustInitQuantity(t, 1000),
					staking.KindRuntimeCompute:    mustInitQuantity(t, 1000),
					staking.KindRuntimeKeyManager: mustInitQuantity(t, 1000),
				},
				DebondingInterval: 2,
				RewardSchedule: []staking.RewardStep{
					{
						Until: 32,
						Scale: mustInitQuantity(t, 1000),
					},
				},
				SigningRewardThresholdNumerator:   1,
				SigningRewardThresholdDenominator: 2,
				CommissionScheduleRules: staking.CommissionScheduleRules{
					RateChangeInterval: 1,
					RateBoundLead:      3,
					MaxRateSteps:       4,
					MaxBoundSteps:      4,
				},
				Slashing: map[staking.SlashReason]staking.Slash{
					staking.SlashDoubleSigning: {
						Amount:         mustInitQuantity(t, 1000),
						FreezeInterval: 32,
					},
				},
				GasCosts: map[transaction.Op]transaction.Gas{
					staking.GasOpAddEscrow:     4,
					staking.GasOpBurn:          4,
					staking.GasOpReclaimEscrow: 4,
					staking.GasOpTransfer:      4,
				},
				MinDelegationAmount:     mustInitQuantity(t, 1000),
				FeeSplitVote:            mustInitQuantity(t, 1),
				FeeSplitPropose:         mustInitQuantity(t, 1),
				RewardFactorEpochSigned: mustInitQuantity(t, 1),
			},
			TotalSupply: mustInitQuantity(t, 2_000_006_000),
			CommonPool:  mustInitQuantity(t, 1_000_000_000),
			Ledger: map[signature.PublicKey]*staking.Account{
				acctRich: {
					General: staking.GeneralAccount{
						Balance: mustInitQuantity(t, 1_000_000_000),
					},
				},
				entity1: {
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance:     mustInitQuantity(t, 2000),
							TotalShares: mustInitQuantity(t, 2000),
						},
						CommissionSchedule: staking.CommissionSchedule{
							Rates: []staking.CommissionRateStep{
								{
									Start: 0,
									Rate:  mustInitQuantity(t, 10_000),
								},
							},
							Bounds: []staking.CommissionRateBoundStep{
								{
									Start:   0,
									RateMin: mustInitQuantity(t, 1000),
									RateMax: mustInitQuantity(t, 50_000),
								},
							},
						},
					},
				},
				entity2: {
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance:     mustInitQuantity(t, 2000),
							TotalShares: mustInitQuantity(t, 2000),
						},
					},
				},
				entity3: {
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance:     mustInitQuantity(t, 2000),
							TotalShares: mustInitQuantity(t, 2000),
						},
					},
				},
			},
		},
		Scheduler: scheduler.Genesis{
			Parameters: scheduler.ConsensusParameters{
				MinValidators:          1,
				MaxValidators:          32,
				MaxValidatorsPerEntity: 1,
			},
		},
	}
	docBytes := marshalAndCheck(t, &doc, "doc")
	msgs := Messages{
		InitReq: types.RequestInitChain{
			Time:          now,
			AppStateBytes: docBytes,
		},
		Blocks: []BlockMessages{
			{
				BeginReq: types.RequestBeginBlock{
					Header: types.Header{
						Time:            now,
						ProposerAddress: node3Addr,
					},
					LastCommitInfo: types.LastCommitInfo{
						Votes: []types.VoteInfo{
							{
								Validator: types.Validator{
									Address: node1Addr,
								},
								SignedLastBlock: true,
							},
							{
								Validator: types.Validator{
									Address: node2Addr,
								},
								SignedLastBlock: true,
							},
							{
								Validator: types.Validator{
									Address: node3Addr,
								},
								SignedLastBlock: true,
							},
						},
					},
				},
				TxReqs: nil,
				EndReq: types.RequestEndBlock{},
			},
			{
				BeginReq: types.RequestBeginBlock{
					Header: types.Header{
						Time:            now,
						ProposerAddress: node1Addr,
					},
					LastCommitInfo: types.LastCommitInfo{
						Votes: []types.VoteInfo{
							{
								Validator: types.Validator{
									Address: node1Addr,
								},
								SignedLastBlock: true,
							},
							{
								Validator: types.Validator{
									Address: node2Addr,
								},
								SignedLastBlock: true,
							},
							{
								Validator: types.Validator{
									Address: node3Addr,
								},
								SignedLastBlock: true,
							},
						},
					},
				},
				TxReqs: []types.RequestDeliverTx{
					{
						Tx: marshalAndCheck(t, &transaction.SignedTransaction{
							Signed: fakeSigned(t, &transaction.Transaction{
								Nonce: 0,
								Fee: &transaction.Fee{
									Amount: mustInitQuantity(t, 40),
									Gas:    4,
								},
								Method: staking.MethodTransfer,
								Body: marshalAndCheck(t, &staking.Transfer{
									To:     entity2,
									Tokens: mustInitQuantity(t, 500),
								}, "tx1body"),
							}, "tx1tx", acctRich),
						}, "tx1"),
					},
				},
				EndReq: types.RequestEndBlock{},
			},
		},
	}
	data := marshalAndCheck(t, &msgs, "msgs")
	require.Equal(t, 1, Fuzz(data), "Fuzz output")
	require.NoError(t, ioutil.WriteFile("/tmp/oasis-node-fuzz2/corpus/manual.f2", data, 0644), "saving fuzz input")
}

func TestEmpty(t *testing.T) {
	require.NoError(t, logging.Initialize(os.Stdout, logging.FmtJSON, logging.LevelDebug, nil), "logging Initialize") // %%%
	local70 := time.Unix(0, 0)
	doc := genesis.Document{
		Time: local70,
		Staking: staking.Genesis{
			Parameters: staking.ConsensusParameters{
				Thresholds: map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            mustInitQuantity(t, 0),
					staking.KindNodeValidator:     mustInitQuantity(t, 0),
					staking.KindNodeCompute:       mustInitQuantity(t, 0),
					staking.KindNodeStorage:       mustInitQuantity(t, 0),
					staking.KindNodeKeyManager:    mustInitQuantity(t, 0),
					staking.KindRuntimeCompute:    mustInitQuantity(t, 0),
					staking.KindRuntimeKeyManager: mustInitQuantity(t, 0),
				},
				Slashing: map[staking.SlashReason]staking.Slash{
					staking.SlashDoubleSigning: {
						Amount:         mustInitQuantity(t, 0),
						FreezeInterval: 0,
					},
				},
				GasCosts: map[transaction.Op]transaction.Gas{
					staking.GasOpAddEscrow:     0,
					staking.GasOpBurn:          0,
					staking.GasOpReclaimEscrow: 0,
					staking.GasOpTransfer:      0,
				},
				FeeSplitVote: mustInitQuantity(t, 1),
			},
		},
		Scheduler: scheduler.Genesis{
			Parameters: scheduler.ConsensusParameters{
				MinValidators:          1,
				MaxValidators:          1,
				MaxValidatorsPerEntity: 1,
			},
		},
	}
	docBytes := marshalAndCheck(t, &doc, "doc")
	msgs := Messages{
		InitReq: types.RequestInitChain{
			Time:          local70,
			AppStateBytes: docBytes,
		},
	}
	data := marshalAndCheck(t, &msgs, "msgs")
	require.Equal(t, 1, Fuzz(data), "Fuzz output")
	require.NoError(t, ioutil.WriteFile("/tmp/oasis-node-fuzz2/corpus/blank.f2", data, 0644), "saving fuzz input")
}
