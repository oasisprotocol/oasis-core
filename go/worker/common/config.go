package common

import (
	tlsPkg "crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	"github.com/oasislabs/oasis-core/go/worker/common/configparser"
)

var (
	// CfgClientPort configures the worker client port.
	CfgClientPort = "worker.client.port"

	cfgClientAddresses = "worker.client.addresses"

	// CfgSentryAddresses configures addresses of sentry nodes the worker
	// should connect to.
	CfgSentryAddresses = "worker.sentry.address"
	// CfgSentryCertFiles configures paths to certificates of the sentry nodes
	// the worker should connect to.
	CfgSentryCertFiles = "worker.sentry.cert_file"

	// CfgRuntimeBackend configures the runtime backend.
	CfgRuntimeBackend = "worker.runtime.backend"
	// CfgRuntimeLoader configures the runtime loader binary.
	CfgRuntimeLoader = "worker.runtime.loader"
	// CfgRuntimeBinary confgures the runtime binary.
	CfgRuntimeBinary = "worker.runtime.binary"

	cfgStorageCommitTimeout = "worker.storage_commit_timeout"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Config contains common worker config.
type Config struct { // nolint: maligned
	ClientPort         uint16
	ClientAddresses    []node.Address
	SentryAddresses    []node.Address
	SentryCertificates []*x509.Certificate

	// RuntimeHost contains configuration for a worker that hosts
	// runtimes. It may be nil if the worker is not configured to
	// host runtimes.
	RuntimeHost *RuntimeHostConfig

	StorageCommitTimeout time.Duration

	logger *logging.Logger
}

// RuntimeHostRuntimeConfig is a single runtime's host configuration.
type RuntimeHostRuntimeConfig struct {
	ID     common.Namespace
	Binary string
}

// RuntimeHostConfig is configuration for a worker that hosts runtimes.
type RuntimeHostConfig struct {
	Backend  string
	Loader   string
	Runtimes map[common.Namespace]RuntimeHostRuntimeConfig
}

// GetNodeAddresses returns worker node addresses.
func (c *Config) GetNodeAddresses() ([]node.Address, error) {
	var addresses []node.Address

	if len(c.ClientAddresses) > 0 {
		addresses = c.ClientAddresses
	} else {
		// Use all non-loopback addresses of this node.
		addrs, err := common.FindAllAddresses()
		if err != nil {
			c.logger.Error("failed to obtain addresses",
				"err", err)
			return nil, err
		}
		var address node.Address
		for _, addr := range addrs {
			if derr := address.FromIP(addr, c.ClientPort); derr != nil {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	return addresses, nil
}

// newConfig creates a new worker config.
func newConfig() (*Config, error) {
	// Parse register address overrides.
	clientAddresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}

	// Parse sentry nodes' addresses.
	sentryAddresses, err := configparser.ParseAddressList(viper.GetStringSlice(CfgSentryAddresses))
	if err != nil {
		return nil, fmt.Errorf("failed to parse sentry address list: %w", err)
	}
	// Get sentry nodes' certificate files.
	sentryCertFiles := viper.GetStringSlice(CfgSentryCertFiles)
	// Check if number of sentry addresses corresponds to the number of sentry
	// certificate files.
	nSentryAddrs, nSentryCertFiles := len(sentryAddresses), len(sentryCertFiles)
	if nSentryAddrs != nSentryCertFiles {
		return nil, fmt.Errorf("worker/registration: configuration error: each sentry node address should have a corresponding certificate file")
	}
	sentryCerts := make([]*x509.Certificate, 0, nSentryCertFiles)
	for _, certFile := range sentryCertFiles {
		var tlsCert *tlsPkg.Certificate
		tlsCert, err = tls.LoadCertificate(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load sentry certificate file %v: %w", certFile, err)
		}
		if len(tlsCert.Certificate) != 1 {
			return nil, fmt.Errorf("sentry certificate file %v should contain exactly 1 certificate in the chain", certFile)
		}
		var x509Cert *x509.Certificate
		x509Cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate file %v: %w", certFile, err)
		}
		sentryCerts = append(sentryCerts, x509Cert)
	}

	cfg := Config{
		ClientPort:           uint16(viper.GetInt(CfgClientPort)),
		ClientAddresses:      clientAddresses,
		SentryAddresses:      sentryAddresses,
		SentryCertificates:   sentryCerts,
		StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),
		logger:               logging.GetLogger("worker/config"),
	}

	// Check if runtime host is configured for the runtimes.
	if runtimeLoader := viper.GetString(CfgRuntimeLoader); runtimeLoader != "" {
		runtimeBinaries, err := runtimeRegistry.ParseRuntimeMap(viper.GetStringSlice(CfgRuntimeBinary))
		if err != nil {
			return nil, err
		}

		cfg.RuntimeHost = &RuntimeHostConfig{
			Backend:  viper.GetString(CfgRuntimeBackend),
			Loader:   runtimeLoader,
			Runtimes: make(map[common.Namespace]RuntimeHostRuntimeConfig),
		}

		for id, path := range runtimeBinaries {
			cfg.RuntimeHost.Runtimes[id] = RuntimeHostRuntimeConfig{
				ID:     id,
				Binary: path,
			}
		}
	}

	return &cfg, nil
}

func init() {
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")
	Flags.StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

	Flags.StringSlice(CfgSentryAddresses, []string{}, fmt.Sprintf("Address(es) of sentry node(s) to connect to (each address should have a corresponding certificate file set in %s)", CfgSentryCertFiles))
	Flags.StringSlice(CfgSentryCertFiles, []string{}, fmt.Sprintf("Certificate file(s) of sentry node(s) to connect to (each certificate file should have a corresponding address set in %s)", CfgSentryAddresses))

	Flags.String(CfgRuntimeBackend, "sandboxed", "Runtime worker host backend")
	Flags.String(CfgRuntimeLoader, "", "Path to runtime loader binary")
	Flags.StringSlice(CfgRuntimeBinary, nil, "Path to runtime binary (format: <runtime-ID>:<path>)")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	_ = viper.BindPFlags(Flags)
}
