package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

func TestComponentConfig(t *testing.T) {
	require := require.New(t)

	cfg := Config{
		Components: []ComponentConfig{
			{
				ID:       component.ID{Kind: component.ROFL, Name: "foo-test"},
				Disabled: false,
			},
		},
	}

	compCfg, ok := cfg.GetComponent(component.ID{Kind: component.ROFL, Name: "foo-test"})
	require.True(ok)
	require.EqualValues(compCfg.ID.Kind, component.ROFL)
	require.EqualValues(compCfg.ID.Name, "foo-test")
	require.False(compCfg.Disabled)

	compCfg, ok = cfg.GetComponent(component.ID{Kind: component.ROFL, Name: "does-not-exist"})
	require.False(ok)
	require.EqualValues(compCfg, ComponentConfig{})

	// Deserialization.
	yamlCfg := `
components:
    - rofl.foo-test
    - id: rofl.another
      disabled: true
`
	var decCfg Config
	err := yaml.Unmarshal([]byte(yamlCfg), &decCfg)
	require.NoError(err, "yaml.Unmarshal")

	compCfg, ok = decCfg.GetComponent(component.ID{Kind: component.ROFL, Name: "foo-test"})
	require.True(ok)
	require.EqualValues(compCfg.ID.Kind, component.ROFL)
	require.EqualValues(compCfg.ID.Name, "foo-test")
	require.False(compCfg.Disabled)

	compCfg, ok = decCfg.GetComponent(component.ID{Kind: component.ROFL, Name: "another"})
	require.True(ok)
	require.EqualValues(compCfg.ID.Kind, component.ROFL)
	require.EqualValues(compCfg.ID.Name, "another")
	require.True(compCfg.Disabled)
}
