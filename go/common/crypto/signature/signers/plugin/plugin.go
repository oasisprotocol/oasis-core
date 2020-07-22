// Package plugin implements the Go plugin signature signer.
package plugin

import (
	"fmt"
	"plugin"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

const (
	// EntryPoint is the entry point (FactoryCtor) expected to be defined
	// in each signer plugin.
	EntryPoint = "GetPluginCtor"

	// SignerName is the name used to identify the plugin signer.
	SignerName = "plugin"
)

// FactoryCtor is the function signature of the EntryPoint symbol
// that is expected to be defined in each plugin.
type FactoryCtor func() signature.SignerFactoryCtor

// FactoryConfig is the plugin factory configuration.
type FactoryConfig struct {
	// Path is the path to the plugin dynamic shared object.
	Path string

	// Config is the plugin configuration.
	Config string
}

// NewFactory creates a new factory backed by the specified plugin
// and plugin configuration.
func NewFactory(config interface{}, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	cfg, ok := config.(*FactoryConfig)
	if !ok {
		return nil, fmt.Errorf("signature/signer/plugin: invalid plugin signer configuration provided")
	}

	p, err := plugin.Open(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to open plugin: %w", err)
	}

	ctorPtr, err := p.Lookup(EntryPoint)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to find entry point: %w", err)
	}

	// Yes, this should use `FactoryCtor` for the type assertion.
	//
	// `plugin.Symbol is func() signature.SignerFactoryCtor, not plugin.FactoryCtor`
	factoryCtor := ctorPtr.(func() signature.SignerFactoryCtor)()
	factory, err := factoryCtor(cfg.Config, roles...)
	if err != nil {
		return nil, fmt.Errorf("signature/signer/plugin: failed to initialize factory: %w", err)
	}

	return factory, nil
}
