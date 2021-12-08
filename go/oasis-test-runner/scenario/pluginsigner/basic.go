package pluginsigner

import (
	"crypto/rand"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	pluginSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/plugin"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	signerTests "github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/signer"
)

// Basic is the basic test case.
var Basic scenario.Scenario = newBasicImpl()

func newBasicImpl() *basicImpl {
	return &basicImpl{
		pluginSignerImpl: *newPluginSignerImpl("basic"),
	}
}

type basicImpl struct {
	pluginSignerImpl
}

func (sc *basicImpl) Clone() scenario.Scenario {
	return &basicImpl{
		pluginSignerImpl: sc.pluginSignerImpl.Clone(),
	}
}

func (sc *basicImpl) Run(childEnv *env.Env) error {
	roles := []signature.SignerRole{
		signature.SignerEntity,
		signature.SignerNode,
		signature.SignerP2P,
		signature.SignerConsensus,
		// signature.SignerVRF not supported because HSMs are potato
	}

	// Initialize the plugin signer.
	pluginName, _ := sc.flags.GetString(cfgPluginName)
	pluginBinary, _ := sc.flags.GetString(cfgPluginBinary)
	pluginConfig, _ := sc.flags.GetString(cfgPluginConfig)
	sf, err := pluginSigner.NewFactory(
		&pluginSigner.FactoryConfig{
			Name:   pluginName,
			Path:   pluginBinary,
			Config: pluginConfig,
		},
		roles...,
	)
	if err != nil {
		return err
	}

	// Generate keys using the new factory.
	for _, v := range roles {
		if _, err = sf.Generate(v, rand.Reader); err != nil {
			return fmt.Errorf("Generate(%v) failed: %w", v, err)
		}
	}

	// Run basic common signer tests.
	if err = signerTests.BasicTests(sf, sc.logger, roles); err != nil {
		return err
	}

	return nil
}
