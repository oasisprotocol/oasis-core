package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

func TestComponentConfig(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	err := runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(err)

	cfg := Config{
		Runtimes: []RuntimeConfig{
			{
				ID: runtimeID,
				Components: []ComponentConfig{
					{
						ID:       component.ID{Kind: component.ROFL, Name: "foo-test"},
						Disabled: false,
					},
				},
			},
		},
	}

	compCfg, ok := cfg.GetComponent(runtimeID, component.ID{Kind: component.ROFL, Name: "foo-test"})
	require.True(ok)
	require.EqualValues(compCfg.ID.Kind, component.ROFL)
	require.EqualValues(compCfg.ID.Name, "foo-test")
	require.False(compCfg.Disabled)

	compCfg, ok = cfg.GetComponent(runtimeID, component.ID{Kind: component.ROFL, Name: "does-not-exist"})
	require.False(ok)
	require.EqualValues(compCfg, ComponentConfig{})

	// Deserialization.
	yamlCfg := `
runtimes:
    - id: 8000000000000000000000000000000000000000000000000000000000000000
      components:
          - rofl.foo-test
          - id: rofl.another
            disabled: true
`
	var decCfg Config
	err = yaml.Unmarshal([]byte(yamlCfg), &decCfg)
	require.NoError(err, "yaml.Unmarshal")

	compCfg, ok = decCfg.GetComponent(runtimeID, component.ID{Kind: component.ROFL, Name: "foo-test"})
	require.True(ok)
	require.EqualValues(compCfg.ID.Kind, component.ROFL)
	require.EqualValues(compCfg.ID.Name, "foo-test")
	require.False(compCfg.Disabled)

	compCfg, ok = decCfg.GetComponent(runtimeID, component.ID{Kind: component.ROFL, Name: "another"})
	require.True(ok)
	require.EqualValues(compCfg.ID.Kind, component.ROFL)
	require.EqualValues(compCfg.ID.Name, "another")
	require.True(compCfg.Disabled)
}

func TestNetworkingConfig(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	err := runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(err)

	cfg := Config{
		Provisioner: RuntimeProvisionerMock,
		Environment: RuntimeEnvironmentAuto,
		Prune: PruneConfig{
			Strategy: "none",
		},
		Runtimes: []RuntimeConfig{
			{
				ID: runtimeID,
				Components: []ComponentConfig{
					{
						ID:       component.ID{Kind: component.ROFL, Name: "foo-test"},
						Disabled: false,
						Networking: NetworkingConfig{
							Incoming: []IncomingNetworkingConfig{
								{
									IP:       "192.168.0.5",
									Protocol: "tcp",
									SrcPort:  80,
									DstPort:  80,
								},
								{
									IP:       "192.168.0.5",
									Protocol: "tcp",
									SrcPort:  81,
									DstPort:  81,
								},
							},
						},
					},
				},
			},
		},
	}
	err = cfg.Validate()
	require.NoError(err)

	cfg.Runtimes[0].Components[0].Networking.Incoming = append(cfg.Runtimes[0].Components[0].Networking.Incoming,
		IncomingNetworkingConfig{
			IP:      "192.168.0.5",
			SrcPort: 80,
		},
	)
	err = cfg.Validate()
	require.ErrorContains(err, "component rofl (foo-test): overlapping incoming IP/protocol/port")

	cfg.Runtimes[0].Components[0].Networking.Incoming[2] = IncomingNetworkingConfig{
		IP:      "0.0.0.0",
		SrcPort: 80,
	}
	err = cfg.Validate()
	require.ErrorContains(err, "component rofl (foo-test): overlapping incoming IP/protocol/port")

	cfg.Runtimes[0].Components[0].Networking.Incoming[0].IP = "0.0.0.0"
	cfg.Runtimes[0].Components[0].Networking.Incoming[2].IP = "192.168.0.5"
	err = cfg.Validate()
	require.ErrorContains(err, "component rofl (foo-test): overlapping incoming IP/protocol/port")

	cfg.Runtimes[0].Components[0].Networking.Incoming[0].IP = "::"
	cfg.Runtimes[0].Components[0].Networking.Incoming[2].IP = "192.168.0.5"
	err = cfg.Validate()
	require.ErrorContains(err, "component rofl (foo-test): overlapping incoming IP/protocol/port")
}
