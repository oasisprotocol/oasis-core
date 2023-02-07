package common

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/config"
)

const (
	// StateDir is the name of the directory located inside the node's data
	// directory which contains the tendermint state.
	StateDir = "tendermint"

	// ConfigDir is the name of the Tendermint configuration directory.
	ConfigDir = "config"
)

// GetExternalAddress returns the configured tendermint external address.
func GetExternalAddress() (*url.URL, error) {
	addrURI := config.GlobalConfig.Consensus.ExternalAddress
	if addrURI == "" {
		addrURI = config.GlobalConfig.Consensus.ListenAddress
	}
	if addrURI == "" {
		return nil, fmt.Errorf("tendermint: no external address configured")
	}

	u, err := url.Parse(addrURI)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address URL: %w", err)
	}

	if u.Scheme != "tcp" {
		return nil, fmt.Errorf("tendermint: external address has invalid scheme: '%v'", u.Scheme)
	}

	// Handle the case when no IP is explicitly configured, and the
	// default value is used.
	if u.Hostname() == "0.0.0.0" {
		var port string
		if _, port, err = net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("tendermint: malformed external address host/port: %w", err)
		}

		ip := common.GuessExternalAddress()
		if ip == nil {
			return nil, fmt.Errorf("tendermint: failed to guess external address")
		}

		u.Host = ip.String() + ":" + port
	}

	return u, nil
}

// InitDataDir initializes the data directory for Tendermint.
func InitDataDir(dataDir string) error {
	subDirs := []string{
		ConfigDir,
		"data", // Required by `tendermint/privval/FilePV.Save()`.
	}

	if err := common.Mkdir(dataDir); err != nil {
		return err
	}

	for _, subDir := range subDirs {
		if err := common.Mkdir(filepath.Join(dataDir, subDir)); err != nil {
			return err
		}
	}

	return nil
}
