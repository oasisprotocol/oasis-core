package plugin

import (
	"net/rpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

var _ Signer = (*rpcClient)(nil)

type rpcServer struct {
	impl Signer
}

// RPCInitArgs is exposed entirely to placate `net/rpc`.
type RPCInitArgs struct {
	Config string
	Roles  []signature.SignerRole
}

// RPCLoadArgs is exposed entirely to placate `net/rpc`.
type RPCLoadArgs struct {
	Role         signature.SignerRole
	MustGenerate bool
}

// RPCContextSignArgs is exposed entirely to placate `net/rpc`.
type RPCContextSignArgs struct {
	Role       signature.SignerRole
	RawContext signature.Context
	Message    []byte
}

func (m *rpcServer) Initialize(args *RPCInitArgs, resp *interface{}) error {
	return m.impl.Initialize(args.Config, args.Roles...)
}

func (m *rpcServer) Load(args *RPCLoadArgs, resp *interface{}) error {
	return m.impl.Load(args.Role, args.MustGenerate)
}

func (m *rpcServer) Public(role signature.SignerRole, resp *signature.PublicKey) error {
	pk, err := m.impl.Public(role)
	*resp = pk
	return err
}

func (m *rpcServer) ContextSign(args *RPCContextSignArgs, resp *[]byte) error {
	sig, err := m.impl.ContextSign(args.Role, args.RawContext, args.Message)
	*resp = sig
	return err
}

type rpcClient struct {
	client *rpc.Client
}

func (m *rpcClient) Initialize(config string, roles ...signature.SignerRole) error {
	var resp interface{}
	return m.client.Call(
		"Plugin.Initialize",
		&RPCInitArgs{
			Config: config,
			Roles:  roles,
		},
		&resp,
	)
}

func (m *rpcClient) Load(role signature.SignerRole, mustGenerate bool) error {
	var resp interface{}
	return m.client.Call(
		"Plugin.Load",
		&RPCLoadArgs{
			Role:         role,
			MustGenerate: mustGenerate,
		},
		&resp,
	)
}

func (m *rpcClient) Public(role signature.SignerRole) (signature.PublicKey, error) {
	var resp signature.PublicKey
	err := m.client.Call(
		"Plugin.Public",
		role,
		&resp,
	)
	return resp, err
}

func (m *rpcClient) ContextSign(role signature.SignerRole, rawContext signature.Context, message []byte) ([]byte, error) {
	var resp []byte
	err := m.client.Call(
		"Plugin.ContextSign",
		&RPCContextSignArgs{
			Role:       role,
			RawContext: rawContext,
			Message:    message,
		},
		&resp,
	)
	return resp, err
}
