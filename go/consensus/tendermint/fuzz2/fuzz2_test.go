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

func mustInitPublicKey(hex string) (pk signature.PublicKey) {
	if err := pk.UnmarshalHex(hex); err != nil {
		panic(err)
	}
	return
}

func mustInitQuantity(i int64) (q quantity.Quantity) {
	if err := q.FromInt64(i); err != nil {
		panic(err)
	}
	return
}

func mustInitAddress(addr string) (a node.Address) {
	if err := a.UnmarshalText([]byte(addr)); err != nil {
		panic(err)
	}
	return
}

func publicKeyWithCert(cert *tls.Certificate) (signature.PublicKey, *tls.Certificate) {
	return memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey)).Public(), cert
}

func mustGenerateCert() (signature.PublicKey, *tls.Certificate) {
	cert, err := tlsCert.Generate(identity.CommonName)
	if err != nil {
		panic(err)
	}
	return publicKeyWithCert(cert)
}

func TestNondeterministic(t *testing.T) {
	fmt.Printf("\tnow = time.Unix(%d, 0)\n", time.Now().Unix())
	for i := 0; i < 3; i++ {
		_, cert := mustGenerateCert()
		certPEM, keyPEM, err := tlsCert.ExportPEM(cert)
		require.NoError(t, err, "ExportPEM")
		fmt.Printf("\tnode%dCom, node%dCert = mustInitCert([]byte(`\n%s`), []byte(`\n%s`))\n", i+1, i+1, certPEM, keyPEM)
	}
}

func mustInitCert(certPEM []byte, keyPEM []byte) (signature.PublicKey, *tls.Certificate) {
	cert, err := tlsCert.ImportPEM(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return publicKeyWithCert(cert)
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

var (
	now                 = time.Unix(1585257884, 0)
	acctRich            = mustInitPublicKey("7200000000000000000000000000000000000000000000000000000000000000")
	entity1             = mustInitPublicKey("3165000000000000000000000000000000000000000000000000000000000000")
	entity2             = mustInitPublicKey("3265000000000000000000000000000000000000000000000000000000000000")
	entity3             = mustInitPublicKey("3365000000000000000000000000000000000000000000000000000000000000")
	node1               = mustInitPublicKey("316e000000000000000000000000000000000000000000000000000000000000")
	node2               = mustInitPublicKey("326e000000000000000000000000000000000000000000000000000000000000")
	node3               = mustInitPublicKey("336e000000000000000000000000000000000000000000000000000000000000")
	node1Com, node1Cert = mustInitCert([]byte(`
-----BEGIN CERTIFICATE-----
MIIBCTCBvKADAgECAgEBMAUGAytlcDAVMRMwEQYDVQQDEwpvYXNpcy1ub2RlMB4X
DTIwMDMyNjIwMjQ0NFoXDTIxMDMyNjIxMjQ0NFowFTETMBEGA1UEAxMKb2FzaXMt
bm9kZTAqMAUGAytlcAMhAPMHK5MydBYSVw1hWDezf5nN1LGZt1Felx1qJzw+fumB
ozEwLzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMAUGAytlcANBAAV8WIn3NAacCPvz3M7eZrDU4a+KE6D198wqMHDuQbyRjuk7
Dh2XPJHycSpisMl1HAJ5OtEu5VUNqEaxk3MkjQc=
-----END CERTIFICATE-----
`), []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPUgVMPL+CvziUOANxoMkFOpqZo9lYz1UwWe6PMQx+hn
-----END PRIVATE KEY-----
`))
	node2Com, node2Cert = mustInitCert([]byte(`
-----BEGIN CERTIFICATE-----
MIIBCTCBvKADAgECAgEBMAUGAytlcDAVMRMwEQYDVQQDEwpvYXNpcy1ub2RlMB4X
DTIwMDMyNjIwMjQ0NFoXDTIxMDMyNjIxMjQ0NFowFTETMBEGA1UEAxMKb2FzaXMt
bm9kZTAqMAUGAytlcAMhAC6xkJtfGGVP7RRhWCbf8d2RB/1eoDoKa3mqTBhf7dph
ozEwLzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMAUGAytlcANBANimX8YX3A84DBUc5S4Q0GW6HcP3YJF54cQesHr2VQRykzYH
PZvjSGg6Rmvw/AX0DfrnggIILrZ2hRVgACxmuA8=
-----END CERTIFICATE-----
`), []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG9cGQgDOvjP06UZ/HWkczolEtU4qUNPbDF6j1Hmjx4/
-----END PRIVATE KEY-----
`))
	node3Com, node3Cert = mustInitCert([]byte(`
-----BEGIN CERTIFICATE-----
MIIBCTCBvKADAgECAgEBMAUGAytlcDAVMRMwEQYDVQQDEwpvYXNpcy1ub2RlMB4X
DTIwMDMyNjIwMjQ0NFoXDTIxMDMyNjIxMjQ0NFowFTETMBEGA1UEAxMKb2FzaXMt
bm9kZTAqMAUGAytlcAMhAGUANvxC37OUUiJOCqN7Y18RbIJxLNhAl3XxrzZ65zIF
ozEwLzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMAUGAytlcANBAHSCGf77cG9n6O2hE/bDH5PNF7Txl6GNaQNyQXIwtfohcjvb
ZoSC/UGZXIdy3lZOaWkX9kdKUHwE94Qk2IeqLgk=
-----END CERTIFICATE-----
`), []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKPzSR5SdIQMWMSRMWaBXuTO9jWMmaqEg5r17pztFRvz
-----END PRIVATE KEY-----
`))
	node1P2P  = mustInitPublicKey("31706e0000000000000000000000000000000000000000000000000000000000")
	node2P2P  = mustInitPublicKey("32706e0000000000000000000000000000000000000000000000000000000000")
	node3P2P  = mustInitPublicKey("33706e0000000000000000000000000000000000000000000000000000000000")
	node1Cons = mustInitPublicKey("31636e0000000000000000000000000000000000000000000000000000000000")
	node2Cons = mustInitPublicKey("32636e0000000000000000000000000000000000000000000000000000000000")
	node3Cons = mustInitPublicKey("33636e0000000000000000000000000000000000000000000000000000000000")
	node1Addr = crypto.PublicKeyToTendermint(&node1Cons).Address()
	node2Addr = crypto.PublicKeyToTendermint(&node2Cons).Address()
	node3Addr = crypto.PublicKeyToTendermint(&node3Cons).Address()
)

func TestCannedRIC(t *testing.T) {
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
									Address: mustInitAddress("1.0.0.1:26656"),
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
									Address: mustInitAddress("1.0.0.2:26656"),
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
									Address: mustInitAddress("1.0.0.3:26656"),
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
					staking.KindEntity:            mustInitQuantity(1000),
					staking.KindNodeValidator:     mustInitQuantity(1000),
					staking.KindNodeCompute:       mustInitQuantity(1000),
					staking.KindNodeStorage:       mustInitQuantity(1000),
					staking.KindNodeKeyManager:    mustInitQuantity(1000),
					staking.KindRuntimeCompute:    mustInitQuantity(1000),
					staking.KindRuntimeKeyManager: mustInitQuantity(1000),
				},
				DebondingInterval: 2,
				RewardSchedule: []staking.RewardStep{
					{
						Until: 32,
						Scale: mustInitQuantity(1000),
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
						Amount:         mustInitQuantity(1000),
						FreezeInterval: 32,
					},
				},
				GasCosts: map[transaction.Op]transaction.Gas{
					staking.GasOpAddEscrow:     4,
					staking.GasOpBurn:          4,
					staking.GasOpReclaimEscrow: 4,
					staking.GasOpTransfer:      4,
				},
				MinDelegationAmount:     mustInitQuantity(1000),
				FeeSplitVote:            mustInitQuantity(1),
				FeeSplitPropose:         mustInitQuantity(1),
				RewardFactorEpochSigned: mustInitQuantity(1),
			},
			TotalSupply: mustInitQuantity(2_000_006_000),
			CommonPool:  mustInitQuantity(1_000_000_000),
			Ledger: map[signature.PublicKey]*staking.Account{
				acctRich: {
					General: staking.GeneralAccount{
						Balance: mustInitQuantity(1_000_000_000),
					},
				},
				entity1: {
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance:     mustInitQuantity(2000),
							TotalShares: mustInitQuantity(2000),
						},
						CommissionSchedule: staking.CommissionSchedule{
							Rates: []staking.CommissionRateStep{
								{
									Start: 0,
									Rate:  mustInitQuantity(10_000),
								},
							},
							Bounds: []staking.CommissionRateBoundStep{
								{
									Start:   0,
									RateMin: mustInitQuantity(1000),
									RateMax: mustInitQuantity(50_000),
								},
							},
						},
					},
				},
				entity2: {
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance:     mustInitQuantity(2000),
							TotalShares: mustInitQuantity(2000),
						},
					},
				},
				entity3: {
					Escrow: staking.EscrowAccount{
						Active: staking.SharePool{
							Balance:     mustInitQuantity(2000),
							TotalShares: mustInitQuantity(2000),
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
	ric := types.RequestInitChain{
		Time:          now,
		AppStateBytes: docBytes,
	}
	cannedRIC = marshalAndCheck(t, &ric, "request init chain")
	fmt.Printf("canned ric %#02v\n", cannedRIC)
}

func TestSimpleRIC(t *testing.T) {
	local70 := time.Unix(0, 0)
	doc := genesis.Document{
		Time: local70,
		Staking: staking.Genesis{
			Parameters: staking.ConsensusParameters{
				Thresholds: map[staking.ThresholdKind]quantity.Quantity{
					staking.KindEntity:            mustInitQuantity(0),
					staking.KindNodeValidator:     mustInitQuantity(0),
					staking.KindNodeCompute:       mustInitQuantity(0),
					staking.KindNodeStorage:       mustInitQuantity(0),
					staking.KindNodeKeyManager:    mustInitQuantity(0),
					staking.KindRuntimeCompute:    mustInitQuantity(0),
					staking.KindRuntimeKeyManager: mustInitQuantity(0),
				},
				Slashing: map[staking.SlashReason]staking.Slash{
					staking.SlashDoubleSigning: {
						Amount:         mustInitQuantity(0),
						FreezeInterval: 0,
					},
				},
				GasCosts: map[transaction.Op]transaction.Gas{
					staking.GasOpAddEscrow:     0,
					staking.GasOpBurn:          0,
					staking.GasOpReclaimEscrow: 0,
					staking.GasOpTransfer:      0,
				},
				FeeSplitVote: mustInitQuantity(1),
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
	ric := types.RequestInitChain{
		Time:          local70,
		AppStateBytes: docBytes,
	}
	cannedRIC = marshalAndCheck(t, &ric, "request init chain")
	fmt.Printf("canned ric %#02v\n", cannedRIC)
}

func TestFuzz(t *testing.T) {
	require.NoError(t, logging.Initialize(os.Stdout, logging.FmtJSON, logging.LevelDebug, nil), "logging Initialize") // %%%
	msgs := Messages{
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
									Amount: mustInitQuantity(40),
									Gas:    4,
								},
								Method: staking.MethodTransfer,
								Body: marshalAndCheck(t, &staking.Transfer{
									To:     entity2,
									Tokens: mustInitQuantity(500),
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
	msgs := Messages{}
	data := marshalAndCheck(t, &msgs, "msgs")
	require.Equal(t, 1, Fuzz(data), "Fuzz output")
	require.NoError(t, ioutil.WriteFile("/tmp/oasis-node-fuzz2/corpus/blank.f2", data, 0644), "saving fuzz input")
}
