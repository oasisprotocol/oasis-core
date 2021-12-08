// Package plugin implements the Go plugin signature signer.
package plugin

import (
	"fmt"
	"io"
	"net/rpc"
	"os/exec"
	"sync"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/syscall"
)

const (
	// SignerName is the name used to identify the plugin backed signer.
	SignerName = "plugin"

	pluginName = "oasis_core_signer"
)

var (
	_ signature.SignerFactory = (*wrapperFactory)(nil)
	_ signature.Signer        = (*wrapperSigner)(nil)
	_ plugin.Plugin           = (*signerPlugin)(nil)

	// Sigh, yet another logging library. :(
	nullLogger = hclog.NewNullLogger()
)

func handshakeConfigForName(name string) plugin.HandshakeConfig {
	return plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "OASIS_CORE_SIGNER_PLUGIN",
		MagicCookieValue: name,
	}
}

// FactoryConfig is the plugin factory configuration.
type FactoryConfig struct {
	// Name is the expected human readable name of the plugin (eg: "ledger", "memory")
	Name string

	// Path is the path to the plugin dynamic shared object.
	Path string

	// Config is the plugin configuration.
	Config string
}

// Serve instantiates and serves a concrete Signer instance as a plugin.
// This is intended to be called from the plugin's `main()`.
func Serve(name string, impl Signer) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfigForName(name),
		Plugins: map[string]plugin.Plugin{
			pluginName: &signerPlugin{
				impl: impl,
			},
		},
		Logger: nullLogger,
	})
}

// NewFactory creates a new factory backed by the specified plugin
// and plugin configuration.
func NewFactory(config interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	cfg, ok := config.(*FactoryConfig)
	if !ok {
		return nil, fmt.Errorf("signature/signer/plugin: invalid plugin signer configuration provided")
	}

	if cfg.Name == "" {
		return nil, fmt.Errorf("signature/signer/plugin: a plugin name must be specified")
	}

	// It's not like all the cheap HSMs people seem to like using is going
	// to support ECVRF anytime soon, when they don't even fully support
	// RFC 8032.
	for _, role := range roles {
		if role == signature.SignerVRF {
			return nil, signature.ErrVRFNotSupported
		}
	}

	// Why yes, the correct thing to do is to call `client.Kill`,
	// when we are done with the plugin.  Alas there's no good
	// way to do that while using `os.Exit`.
	//
	// At least ensure that child processes get killed in sensible
	// environments.  If people have a problem with this they can
	// do one or more of:
	//
	//  1. Get rid of the ~180 instances of `os.Exit`
	//  2. Complain to the Go developers to make `plugin` not suck.
	//  3. Complain to their OS vendor to implement PR_SET_PDEATH_SIG`.
	//  4. Complain to Docker to make Docker not suck (reaping zombies
	//     isn't that hard).
	//
	// We do use managed plugins so that in the graceful exit case,
	// the cleanup will be done at least.
	cmd := exec.Command(cfg.Path) // nolint: gosec
	cmd.SysProcAttr = syscall.CmdAttrs

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshakeConfigForName(cfg.Name),
		Plugins: map[string]plugin.Plugin{
			pluginName: &signerPlugin{},
		},
		Cmd:      cmd,
		Logger:   nullLogger,
		Managed:  true,
		AutoMTLS: true,
	})

	// Despite what is said above, we can at least clean up if things go
	// wrong as part of the initialization process.
	ok = false
	defer func() {
		if !ok {
			client.Kill()
		}
	}()

	rpcClient, err := client.Client()
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to connect to plugin: %w", err)
	}

	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to request plugin: %w", err)
	}

	pluginSigner := raw.(Signer)
	if err = pluginSigner.Initialize(cfg.Config, roles...); err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to initialize plugin: %w", err)
	}

	wf := &wrapperFactory{
		pluginSigner: pluginSigner,
		signers:      make(map[signature.SignerRole]*wrapperSigner),
		name:         cfg.Name,
	}
	for _, v := range roles {
		wf.signers[v] = &wrapperSigner{
			wf:   wf,
			role: v,
		}
	}

	ok = true

	return wf, nil
}

type wrapperFactory struct {
	sync.Mutex

	pluginSigner Signer
	signers      map[signature.SignerRole]*wrapperSigner
	name         string
}

func (wf *wrapperFactory) EnsureRole(role signature.SignerRole) error {
	wf.Lock()
	defer wf.Unlock()

	if wf.signers[role] == nil {
		return signature.ErrRoleMismatch
	}
	return nil
}

func (wf *wrapperFactory) Generate(role signature.SignerRole, _rng io.Reader) (signature.Signer, error) {
	if role == signature.SignerVRF {
		return nil, signature.ErrVRFNotSupported
	}

	wf.Lock()
	defer wf.Unlock()

	wrapper := wf.signers[role]
	if wrapper == nil {
		return nil, signature.ErrRoleMismatch
	}

	if wrapper.publicKey != nil {
		return nil, fmt.Errorf("signature/signer/plugin: refusing to overwrite existing key")
	}

	return wrapper.doLoad(true)
}

func (wf *wrapperFactory) Load(role signature.SignerRole) (signature.Signer, error) {
	if role == signature.SignerVRF {
		return nil, signature.ErrVRFNotSupported
	}

	wf.Lock()
	defer wf.Unlock()

	wrapper := wf.signers[role]
	if wrapper == nil {
		return nil, signature.ErrRoleMismatch
	}

	if wrapper.publicKey != nil {
		return wrapper, nil
	}

	return wrapper.doLoad(false)
}

type wrapperSigner struct {
	wf *wrapperFactory

	publicKey *signature.PublicKey
	role      signature.SignerRole
}

func (ws *wrapperSigner) Public() signature.PublicKey {
	return *ws.publicKey
}

func (ws *wrapperSigner) ContextSign(context signature.Context, message []byte) ([]byte, error) {
	// Prepare the context (plugin can't handle chain separation).
	rawCtx, err := signature.PrepareSignerContext(context)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to prepare context: %w", err)
	}

	role := ws.role
	sig, err := ws.wf.pluginSigner.ContextSign(role, signature.Context(rawCtx), message)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to sign: %w", err)
	}

	return sig, nil
}

func (ws *wrapperSigner) String() string {
	return fmt.Sprintf("[%s plugin signer: %s]", ws.wf.name, ws.publicKey)
}

func (ws *wrapperSigner) Reset() {
	// Not supported for the plugin signer.
}

func (ws *wrapperSigner) doLoad(mustGenerate bool) (signature.Signer, error) {
	role := ws.role
	if err := ws.wf.pluginSigner.Load(role, mustGenerate); err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to load/generate key: %w", err)
	}
	pk, err := ws.wf.pluginSigner.Public(role)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to obtain public key: %w", err)
	}

	// Cache the public key for easy re-use and to indicate that this
	// signer is fully initialized.
	ws.publicKey = &pk

	return ws, nil
}

type signerPlugin struct {
	impl Signer
}

func (p *signerPlugin) Server(_broker *plugin.MuxBroker) (interface{}, error) {
	return &rpcServer{
		impl: p.impl,
	}, nil
}

func (signerPlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &rpcClient{
		client: c,
	}, nil
}
