// +build gofuzz

package fuzz2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/fm"
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

func marshalBytes(dst io.Writer, v []byte) {
	if v == nil {
		if err := binary.Write(dst, binary.LittleEndian, uint16(0xfffe)); err != nil {
			panic(err)
		}
		return
	}
	l := len(v)
	if l >= 0xffff {
		panic(fmt.Sprintf("bytes len %d too long (max %d)", l, 0xffff-2))
	}
	if l == 0 {
		if err := binary.Write(dst, binary.LittleEndian, uint16(0xffff)); err != nil {
			panic(err)
		}
		return
	}
	if err := binary.Write(dst, binary.LittleEndian, uint16(l)); err != nil {
		panic(err)
	}
	if err := binary.Write(dst, binary.LittleEndian, v); err != nil {
		panic(err)
	}
}

func marshalInner(dst io.Writer, v reflect.Value, indent int) {
	if !v.CanInterface() {
		fmt.Print("(unexported)")
		return
	}
	switch v.Type() {
	case reflect.TypeOf([]byte{}):
		fmt.Printf("(bytes \"%x\")", v.Bytes())
		marshalBytes(dst, v.Bytes())
		return
	case reflect.TypeOf(time.Time{}):
		t := v.Interface().(time.Time)
		fmt.Printf("(time \"%v\")", t)
		sec := t.Unix()
		if sec >= 1000*365*24*60*60 {
			panic(fmt.Sprintf("time %v sec is too late (max %v)", t, time.Unix(1000*365*24*60*60-1, 0)))
		}
		if err := binary.Write(dst, binary.LittleEndian, sec); err != nil {
			panic(err)
		}
		if err := binary.Write(dst, binary.LittleEndian, int64(t.Nanosecond())); err != nil {
			panic(err)
		}
		return
	case reflect.TypeOf(signature.PublicKey{}):
		pk := v.Interface().(signature.PublicKey)
		fmt.Printf("(public_key \"%x\")", pk[:])
		if err := binary.Write(dst, binary.LittleEndian, pk); err != nil {
			panic(err)
		}
		return
	case reflect.TypeOf(signature.RawSignature{}):
		s := v.Interface().(signature.RawSignature)
		fmt.Printf("(raw_signature \"%x\")", s[:])
		if err := binary.Write(dst, binary.LittleEndian, s); err != nil {
			panic(err)
		}
		return
	case reflect.TypeOf(quantity.Quantity{}):
		q := v.Interface().(quantity.Quantity)
		fmt.Printf("(quantity %v)", q)
		inner := q.ToBigInt()
		if !inner.IsUint64() {
			panic(fmt.Sprintf("quantity %v is too large (max %d)", q, uint64(math.MaxUint64)))
		}
		if err := binary.Write(dst, binary.LittleEndian, inner.Uint64()); err != nil {
			panic(err)
		}
		return
	case reflect.TypeOf(node.Address{}):
		addr := v.Interface().(node.Address)
		fmt.Printf("(address \"%v\")", addr)
		if len(addr.IP) != 16 {
			panic(fmt.Sprintf("address IP %v must be length 16", addr.IP))
		}
		if err := binary.Write(dst, binary.LittleEndian, addr.IP); err != nil {
			panic(err)
		}
		if err := binary.Write(dst, binary.LittleEndian, uint64(addr.Port)); err != nil {
			panic(err)
		}
		if addr.Zone != "" {
			panic(fmt.Sprintf("address zone %q not supported", addr.Zone))
		}
		return
	case reflect.TypeOf(transaction.Op("")):
		op := v.Interface().(transaction.Op)
		fmt.Printf("(op \"%v\")", op)
		if len(op) > 16 {
			panic(fmt.Sprintf("op %q too long (max 16)", op))
		}
		var buf [16]byte
		copy(buf[:], op)
		if err := binary.Write(dst, binary.LittleEndian, buf[:]); err != nil {
			panic(err)
		}
		return
	case reflect.TypeOf(transaction.MethodName("")):
		m := v.Interface().(transaction.MethodName)
		fmt.Printf("(method_name \"%v\")", m)
		if len(m) > 16 {
			panic(fmt.Sprintf("method name %q too long (max 16)", m))
		}
		var buf [16]byte
		copy(buf[:], m)
		if err := binary.Write(dst, binary.LittleEndian, buf[:]); err != nil {
			panic(err)
		}
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		fmt.Printf("(bool %v)", v.Bool())
		var src uint64
		if v.Bool() {
			src = 1
		}
		if err := binary.Write(dst, binary.LittleEndian, src); err != nil {
			panic(err)
		}
	case reflect.Int:
		fmt.Printf("(int %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, v.Int()); err != nil {
			panic(err)
		}
	case reflect.Int32:
		fmt.Printf("(int32 %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, v.Int()); err != nil {
			panic(err)
		}
	case reflect.Int64:
		fmt.Printf("(int64 %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, v.Int()); err != nil {
			panic(err)
		}
	case reflect.Uint8:
		fmt.Printf("(uint8 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, v.Uint()); err != nil {
			panic(err)
		}
	case reflect.Uint32:
		fmt.Printf("(uint32 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, v.Uint()); err != nil {
			panic(err)
		}
	case reflect.Uint64:
		fmt.Printf("(uint64 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, v.Uint()); err != nil {
			panic(err)
		}
	case reflect.Array:
		fmt.Printf("(array\n%s", strings.Repeat("\t", indent))
		if err := binary.Write(dst, binary.LittleEndian, uint64(0x0DDD_DDDD_DDDD_DDDD)); err != nil {
			panic(err)
		}
		for i := 0; i < v.Len(); i++ {
			fmt.Print("\t(item ")
			marshalInner(dst, v.Index(i), indent+1)
			fmt.Printf(")\n%s", strings.Repeat("\t", indent))
		}
		fmt.Print(")")
	case reflect.Map:
		if v.IsNil() {
			fmt.Print("(map nil)")
			if err := binary.Write(dst, binary.LittleEndian, uint64(0x0CCC_CCCC_CCCC_CCCC)); err != nil {
				panic(err)
			}
		} else {
			fmt.Printf("(map\n%s", strings.Repeat("\t", indent))
			if err := binary.Write(dst, binary.LittleEndian, uint64(0x0DDD_DDDD_DDDD_DDDD)); err != nil {
				panic(err)
			}
			if v.Len() > 10 {
				panic(fmt.Sprintf("map len %d too long (max 10)", v.Len()))
			}
			if err := binary.Write(dst, binary.LittleEndian, uint64(v.Len())<<32); err != nil {
				panic(err)
			}
			mr := v.MapRange()
			for mr.Next() {
				fmt.Print("\t(item ")
				marshalInner(dst, mr.Key(), indent+1)
				fmt.Print(" ")
				marshalInner(dst, mr.Value(), indent+1)
				fmt.Printf(")\n%s", strings.Repeat("\t", indent))
			}
			fmt.Print(")")
		}
	case reflect.Ptr:
		if v.IsNil() {
			fmt.Print("(ptr nil)")
			if err := binary.Write(dst, binary.LittleEndian, uint64(0x0CCC_CCCC_CCCC_CCCC)); err != nil {
				panic(err)
			}
		} else {
			fmt.Print("(ptr ")
			if err := binary.Write(dst, binary.LittleEndian, uint64(0x0DDD_DDDD_DDDD_DDDD)); err != nil {
				panic(err)
			}
			marshalInner(dst, v.Elem(), indent)
			fmt.Print(")")
		}
	case reflect.Slice:
		if v.IsNil() {
			fmt.Print("(slice nil)")
			if err := binary.Write(dst, binary.LittleEndian, uint64(0x0CCC_CCCC_CCCC_CCCC)); err != nil {
				panic(err)
			}
		} else {
			fmt.Printf("(slice\n%s", strings.Repeat("\t", indent))
			if err := binary.Write(dst, binary.LittleEndian, uint64(0x0DDD_DDDD_DDDD_DDDD)); err != nil {
				panic(err)
			}
			if v.Len() > 10 {
				panic(fmt.Sprintf("slice len %d too long (max 10)", v.Len()))
			}
			if err := binary.Write(dst, binary.LittleEndian, uint64(v.Len())<<32); err != nil {
				panic(err)
			}
			for i := 0; i < v.Len(); i++ {
				fmt.Print("\t(item ")
				marshalInner(dst, v.Index(i), indent+1)
				fmt.Printf(")\n%s", strings.Repeat("\t", indent))
			}
			fmt.Print(")")
		}
	case reflect.String:
		fmt.Printf("(string %+q)", v.String())
		marshalBytes(dst, []byte(v.String()))
	case reflect.Struct:
		t := v.Type()
		fmt.Printf("(struct '%s\n%s", t.Name(), strings.Repeat("\t", indent))
		for i := 0; i < v.NumField(); i++ {
			fmt.Printf("\t(field '%s ", t.Field(i).Name)
			marshalInner(dst, v.Field(i), indent+1)
			fmt.Printf(")\n%s", strings.Repeat("\t", indent))
		}
		fmt.Print(")")
	default:
		panic(fmt.Sprintf("not supported kind %d (line %d) %#v", v.Kind(), v.Kind()+233, v))
	}
}

func marshal(v interface{}) []byte {
	var buf bytes.Buffer
	// gofuzzFuzzer.NilChance(0.1).NumElements(0, 10)
	if err := binary.Write(&buf, binary.LittleEndian, byte(128)); err != nil {
		panic(err)
	}
	marshalInner(&buf, reflect.ValueOf(v), 0)
	fmt.Println()
	return buf.Bytes()
}

func marshalAndCheck(t *testing.T, v interface{}, msg string) []byte {
	data := marshal(v)
	fmt.Printf("data [%x]\n", data)
	v2r := reflect.New(reflect.TypeOf(v))
	reflect.ValueOf(fm.MustUnmarshal).Call([]reflect.Value{reflect.ValueOf(data), v2r})
	v2 := v2r.Elem().Interface()
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
					fakeSigned(t, entity.Entity{
						ID:    entity1,
						Nodes: []signature.PublicKey{node1},
					}, "entity1", entity1),
				},
				{
					fakeSigned(t, entity.Entity{
						ID:    entity2,
						Nodes: []signature.PublicKey{node2},
					}, "entity2", entity2),
				},
				{
					fakeSigned(t, entity.Entity{
						ID:    entity3,
						Nodes: []signature.PublicKey{node3},
					}, "entity3", entity3),
				},
			},
			Nodes: []*node.MultiSignedNode{
				{
					fakeMultiSigned(t, node.Node{
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
					fakeMultiSigned(t, node.Node{
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
					fakeMultiSigned(t, node.Node{
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
	docFM := marshalAndCheck(t, doc, "doc")
	msgs := messages{
		InitReq: types.RequestInitChain{
			Time:          now,
			AppStateBytes: docFM,
		},
		Blocks: []blockMessages{
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
						Tx: marshalAndCheck(t, transaction.SignedTransaction{
							Signed: fakeSigned(t, transaction.Transaction{
								Nonce: 0,
								Fee: &transaction.Fee{
									Amount: mustInitQuantity(t, 40),
									Gas:    4,
								},
								Method: staking.MethodTransfer,
								Body: marshalAndCheck(t, staking.Transfer{
									To:     entity2,
									Tokens: mustInitQuantity(t, 500),
								}, "tx1body"),
							}, "tx1-inner", acctRich),
						}, "tx1-outer"),
					},
				},
				EndReq: types.RequestEndBlock{},
			},
		},
	}
	data := marshalAndCheck(t, msgs, "msgs")
	require.Equal(t, 1, Fuzz(data), "Fuzz output")
	require.NoError(t, ioutil.WriteFile("/tmp/oasis-node-fuzz2/corpus/manual.fm", data, 0644), "saving fuzz input")
}
