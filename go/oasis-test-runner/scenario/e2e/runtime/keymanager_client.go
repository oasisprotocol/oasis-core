package runtime

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	kmp2p "github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
)

type keyManagerRPCClient struct {
	host   host.Host
	client rpc.Client
}

func newKeyManagerRPCClient(chainContext string) (*keyManagerRPCClient, error) {
	signer, err := memory.NewFactory().Generate(signature.SignerP2P, rand.Reader)
	if err != nil {
		return nil, err
	}

	listenAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
	if err != nil {
		return nil, err
	}

	host, err := libp2p.New(
		libp2p.ListenAddrs(listenAddr),
		libp2p.Identity(p2p.SignerToPrivKey(signer)),
	)
	if err != nil {
		return nil, err
	}

	pid := protocol.NewRuntimeProtocolID(chainContext, KeyManagerRuntimeID, kmp2p.KeyManagerProtocolID, kmp2p.KeyManagerProtocolVersion)
	client := rpc.NewClient(host, pid)

	return &keyManagerRPCClient{
		host:   host,
		client: client,
	}, nil
}

func (c *keyManagerRPCClient) addKeyManagerAddrToHost(km *oasis.Keymanager) (peer.ID, error) {
	identity, err := km.LoadIdentity()
	if err != nil {
		return "", err
	}

	peerID, err := p2p.PublicKeyToPeerID(identity.P2PSigner.Public())
	if err != nil {
		return "", err
	}

	peerAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", km.P2PPort()))
	if err != nil {
		return "", err
	}

	c.host.Peerstore().AddAddr(peerID, peerAddr, time.Hour)

	return peerID, nil
}

func (c *keyManagerRPCClient) fetchPublicKey(ctx context.Context, generation uint64, peerID peer.ID) (*x25519.PublicKey, error) {
	args := secrets.LongTermKeyRequest{
		Height:     nil,
		ID:         KeyManagerRuntimeID,
		KeyPairID:  secrets.KeyPairID{1, 2, 3},
		Generation: generation,
	}

	req := enclaverpc.Request{
		Method: secrets.RPCMethodGetPublicKey,
		Args:   cbor.Marshal(args),
	}

	p2pReq := kmp2p.CallEnclaveRequest{
		Kind: enclaverpc.KindInsecureQuery,
		Data: cbor.Marshal(req),
	}

	var p2pRsp kmp2p.CallEnclaveResponse
	_, err := c.client.Call(ctx, peerID, kmp2p.MethodCallEnclave, p2pReq, &p2pRsp)
	if err != nil {
		return nil, err
	}

	var rsp enclaverpc.Response
	if err = cbor.Unmarshal(p2pRsp.Data, &rsp); err != nil {
		return nil, err
	}

	if rsp.Body.Error != nil {
		msg := *rsp.Body.Error
		if msg == fmt.Sprintf("master secret generation %d not found", generation) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s", msg)
	}

	var key secrets.SignedPublicKey
	if err = cbor.Unmarshal(rsp.Body.Success, &key); err != nil {
		return nil, err
	}

	return &key.Key, nil
}

func (c *keyManagerRPCClient) fetchEphemeralPublicKey(ctx context.Context, epoch beacon.EpochTime, peerID peer.ID) (*x25519.PublicKey, error) {
	args := secrets.EphemeralKeyRequest{
		Height:    nil,
		ID:        KeyManagerRuntimeID,
		KeyPairID: secrets.KeyPairID{1, 2, 3},
		Epoch:     epoch,
	}

	req := enclaverpc.Request{
		Method: secrets.RPCMethodGetPublicEphemeralKey,
		Args:   cbor.Marshal(args),
	}

	p2pReq := kmp2p.CallEnclaveRequest{
		Kind: enclaverpc.KindInsecureQuery,
		Data: cbor.Marshal(req),
	}

	var p2pRsp kmp2p.CallEnclaveResponse
	_, err := c.client.Call(ctx, peerID, kmp2p.MethodCallEnclave, p2pReq, &p2pRsp)
	if err != nil {
		return nil, err
	}

	var rsp enclaverpc.Response
	if err = cbor.Unmarshal(p2pRsp.Data, &rsp); err != nil {
		return nil, err
	}

	if rsp.Body.Error != nil {
		msg := *rsp.Body.Error
		if msg == fmt.Sprintf("ephemeral secret for epoch %d not found", epoch) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s", msg)
	}

	var key secrets.SignedPublicKey
	if err = cbor.Unmarshal(rsp.Body.Success, &key); err != nil {
		return nil, err
	}

	return &key.Key, nil
}

func (c *keyManagerRPCClient) fetchEphemeralPublicKeyWithRetry(ctx context.Context, epoch beacon.EpochTime, peerID peer.ID) (*x25519.PublicKey, error) {
	var (
		err error
		key *x25519.PublicKey
	)

	retry := backoff.WithContext(backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 5), ctx)
	err = backoff.Retry(func() error {
		key, err = c.fetchEphemeralPublicKey(ctx, epoch, peerID)
		return err
	}, retry)
	if err != nil {
		return nil, err
	}

	return key, err
}
