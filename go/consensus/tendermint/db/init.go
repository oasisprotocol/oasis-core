// Package db implements several Tendermint DB backends.
package db

import (
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	tmconfig "github.com/tendermint/tendermint/config"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db/badger"
)

const cfgBackend = "tendermint.db.backend"

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// GetBackendName returns the currently configured Tendermint database backend.
func GetBackendName() string {
	return viper.GetString(cfgBackend)
}

// GetProvider returns the currently configured Tendermint DBProvider.
func GetProvider() (tmconfig.DBProvider, error) {
	backend := viper.GetString(cfgBackend)

	switch strings.ToLower(backend) {
	case badger.BackendName:
		return badger.DBProvider, nil
	default:
		return nil, fmt.Errorf("tendermint/db: unsupported backend: '%v'", backend)
	}
}

// New constructs a new tendermint DB with the configured backend.
func New(fn string, noSuffix bool) (dbm.DB, error) {
	backend := viper.GetString(cfgBackend)

	switch strings.ToLower(backend) {
	case badger.BackendName:
		return badger.New(fn, noSuffix)
	default:
		return nil, fmt.Errorf("tendermint/db: unsupported backend: '%v'", backend)
	}
}

func init() {
	Flags.String(cfgBackend, badger.BackendName, "tendermint db backend")

	_ = viper.BindPFlags(Flags)
}
