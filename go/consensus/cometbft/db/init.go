// Package db implements several CometBFT DB backends.
package db

import (
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/node"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/badger"
)

const cfgBackend = "cometbft.db.backend"

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// GetBackendName returns the currently configured CometBFT database backend.
func GetBackendName() string {
	return viper.GetString(cfgBackend)
}

// GetProvider returns the currently configured CometBFT DBProvider.
func GetProvider() (node.DBProvider, error) {
	backend := viper.GetString(cfgBackend)

	switch strings.ToLower(backend) {
	case badger.BackendName:
		return badger.DBProvider, nil
	default:
		return nil, fmt.Errorf("cometbft/db: unsupported backend: '%v'", backend)
	}
}

// New constructs a new CometBFT DB with the configured backend.
func New(fn string, noSuffix bool) (dbm.DB, error) {
	backend := viper.GetString(cfgBackend)

	switch strings.ToLower(backend) {
	case badger.BackendName:
		return badger.New(fn, noSuffix)
	default:
		return nil, fmt.Errorf("cometbft/db: unsupported backend: '%v'", backend)
	}
}

func init() {
	Flags.String(cfgBackend, badger.BackendName, "cometbft db backend")

	_ = viper.BindPFlags(Flags)
}
