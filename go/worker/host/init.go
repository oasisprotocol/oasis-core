// Package host implements the ekiden worker host.
package host

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/ias"
)

const (
	cfgWorkerBinary  = "worker.binary"
	cfgRuntimeBinary = "worker.runtime"
	cfgCacheDir      = "worker.cache_dir"

	cfgIASProxy = "worker.ias.proxy_addr"
)

var (
	flagWorkerBinary  string
	flagRuntimeBinary string
	flagCacheDir      string

	flagIASProxy string
)

// New creates a new worker host.
func New(cmd *cobra.Command, identity *signature.PrivateKey, storage storage.Backend) (*Host, error) {
	workerBinary, _ := cmd.Flags().GetString(cfgWorkerBinary)
	runtimeBinary, _ := cmd.Flags().GetString(cfgRuntimeBinary)
	cacheDir, _ := cmd.Flags().GetString(cfgCacheDir)

	// Create new IAS proxy client.
	iasProxy, _ := cmd.Flags().GetString(cfgIASProxy)
	ias, err := ias.New(identity, iasProxy)
	if err != nil {
		return nil, err
	}

	return newHost(workerBinary, runtimeBinary, cacheDir, storage, ias)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagWorkerBinary, cfgWorkerBinary, "", "Path to worker process binary")
	cmd.Flags().StringVar(&flagRuntimeBinary, cfgRuntimeBinary, "", "Path to runtime binary")
	cmd.Flags().StringVar(&flagCacheDir, cfgCacheDir, "", "Path to worker cache directory")

	cmd.Flags().StringVar(&flagIASProxy, cfgIASProxy, "", "IAS proxy address")

	for _, v := range []string{
		cfgWorkerBinary,
		cfgRuntimeBinary,
		cfgCacheDir,
		cfgIASProxy,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
