// Package fixtures provides network configuration fixtures.
package fixtures

import (
	"encoding/json"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
)

var (
	// FileFixtureFlags are command line flags for the fixtures.
	FileFixtureFlags = flag.NewFlagSet("", flag.ContinueOnError)

	// DefaultFixtureFlags are  command line flags for the fixture.default.* flags.
	DefaultFixtureFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

// GetFixture generates fixture object from given file or default fixture, if no fixtures file provided.
func GetFixture() (*oasis.NetworkFixture, error) {
	if viper.IsSet(cfgFile) {
		return newFixtureFromFile(viper.GetString(cfgFile))
	}
	return newDefaultFixture()
}

// DumpFixture dumps given fixture to JSON-encoded bytes.
func DumpFixture(f *oasis.NetworkFixture) ([]byte, error) {
	data, err := json.MarshalIndent(f, "", "    ")
	if err != nil {
		return nil, err
	}

	return data, nil
}
