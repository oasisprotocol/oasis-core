// Package keymanager implements the key manager worker.
package keymanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

const (
	cfgEnabled = "worker.keymanager.enabled"

	cfgTEEHardware   = "worker.keymanager.tee_hardware"
	cfgRuntimeLoader = "worker.keymanager.runtime.loader"
	cfgRuntimeBinary = "worker.keymanager.runtime.binary"
	cfgRuntimeID     = "worker.keymanager.runtime.id"
	cfgMayGenerate   = "worker.keymanager.may_generate"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(cfgEnabled)
}

// New constructs a new key manager worker.
func New(
	dataDir string,
	commonWorker *workerCommon.Worker,
	ias *ias.IAS,
	r *registration.Registration,
	backend api.Backend,
) (*Worker, error) {
	var teeHardware node.TEEHardware
	s := viper.GetString(cfgTEEHardware)
	switch strings.ToLower(s) {
	case "", "invalid":
	case "intel-sgx":
		teeHardware = node.TEEHardwareIntelSGX
	default:
		return nil, fmt.Errorf("invalid TEE hardware: %s", s)
	}

	workerRuntimeLoaderBinary := viper.GetString(cfgRuntimeLoader)
	runtimeBinary := viper.GetString(cfgRuntimeBinary)

	ctx, cancelFn := context.WithCancel(context.Background())

	w := &Worker{
		logger:       logging.GetLogger("worker/keymanager"),
		ctx:          ctx,
		cancelCtx:    cancelFn,
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		commonWorker: commonWorker,
		registration: r,
		backend:      backend,
		enabled:      Enabled(),
		mayGenerate:  viper.GetBool(cfgMayGenerate),
	}

	if w.enabled {
		if !w.commonWorker.Enabled() {
			panic("common worker should have been enabled for key manager worker")
		}

		if err := w.runtimeID.UnmarshalHex(viper.GetString(cfgRuntimeID)); err != nil {
			return nil, errors.Wrap(err, "worker/keymanager: failed to parse runtime ID")
		}

		if workerRuntimeLoaderBinary == "" {
			return nil, fmt.Errorf("worker/keymanager: worker runtime loader binary not configured")
		}
		if runtimeBinary == "" {
			return nil, fmt.Errorf("worker/keymanager: runtime binary not configured")
		}

		w.registration.RegisterRole(w.onNodeRegistration)

		w.workerHostCfg = host.Config{
			Role:           node.RoleKeyManager,
			ID:             w.runtimeID,
			WorkerBinary:   workerRuntimeLoaderBinary,
			RuntimeBinary:  runtimeBinary,
			TEEHardware:    teeHardware,
			IAS:            ias,
			MessageHandler: newHostHandler(w),
		}

		newEnclaveRPCGRPCServer(w)
	}

	return w, nil
}

func init() {
	emptyRoot.Empty()

	Flags.Bool(cfgEnabled, false, "Enable key manager worker")

	Flags.String(cfgTEEHardware, "", "TEE hardware to use for the key manager")
	Flags.String(cfgRuntimeLoader, "", "Path to key manager worker process binary")
	Flags.String(cfgRuntimeBinary, "", "Path to key manager runtime binary")
	Flags.String(cfgRuntimeID, "", "Key manager Runtime ID")
	Flags.Bool(cfgMayGenerate, false, "Key manager may generate new master secret")

	_ = viper.BindPFlags(Flags)
}
