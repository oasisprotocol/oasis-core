package fixtures

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
)

const (
	cfgFile = "fixture.file"
)

// newFixtureFromFile parses given JSON file and creates new fixture object from it.
func newFixtureFromFile(path string) (*oasis.NetworkFixture, error) {
	f := oasis.NetworkFixture{}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("newFixtureFromFile: failed to open fixture file: %w", err)
	}
	if err = json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("newFixtureFromFile: failed to unmarshal JSON from fixture file: %w", err)
	}

	return &f, nil
}

func init() {
	FileFixtureFlags.String(cfgFile, "", "path to JSON-encoded fixture input file")
	_ = viper.BindPFlags(FileFixtureFlags)
}
