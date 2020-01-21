// Package common implements common oasis-node command options and utilities.
package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	ledgerSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/ledger"

	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	// CfgDebugAllowTestKeys is the command line flag to enable the debug test
	// keys.
	CfgDebugAllowTestKeys = "debug.allow_test_keys"

	// CfgDebugRlimit is the command flag to set RLIMIT_NOFILE on launch.
	CfgDebugRlimit = "debug.rlimit"

	cfgConfigFile = "config"
	CfgDataDir    = "datadir"

	badDefaultRlimit = 1024
)

var (
	cfgFile string

	rootLog = logging.GetLogger("oasis-node")

	debugAllowTestKeysFlag = flag.NewFlagSet("", flag.ContinueOnError)
	debugRlimitFlag        = flag.NewFlagSet("", flag.ContinueOnError)

	// RootFlags has the flags that are common across all commands.
	RootFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

// DataDir retuns the data directory iff one is set.
func DataDir() string {
	return viper.GetString(CfgDataDir)
}

// DataDirOrPwd returns the data directory iff one is set, pwd otherwise.
func DataDirOrPwd() (string, error) {
	dataDir := DataDir()
	if dataDir == "" {
		var err error
		if dataDir, err = os.Getwd(); err != nil {
			return "", err
		}
	}
	return dataDir, nil
}

// SignerFactory returns the appropriate SignerFactory based on flags.
func SignerFactory(signerBackend string, signerDir string) (signature.SignerFactory, error) {
	switch signerBackend {
	case ledgerSigner.SignerName:
		config := ledgerSigner.FactoryConfig{
			Address: flags.SignerLedgerAddress(),
			Index:   flags.SignerLedgerIndex(),
		}
		return ledgerSigner.NewFactory(&config, signature.SignerEntity), nil
	case fileSigner.SignerName:
		return fileSigner.NewFactory(signerDir, signature.SignerEntity), nil
	default:
		return nil, fmt.Errorf("unsupported signer backend: %s", signerBackend)
	}
}

// EarlyLogAndExit logs the error and exits.
//
// Note: This routine should only be used prior to the logging system
// being initialized.
func EarlyLogAndExit(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// Init initializes the common environment across all commands.
func Init() error {
	initFns := []func() error{
		initDataDir,
		initLogging,
		initPublicKeyBlacklist,
		initRlimit,
	}

	for _, fn := range initFns {
		if err := fn(); err != nil {
			return err
		}
	}

	rootLog.Debug("common initialization complete")

	return nil
}

// Logger returns the command logger.
func Logger() *logging.Logger {
	return rootLog
}

func init() {
	initLoggingFlags()

	debugAllowTestKeysFlag.Bool(CfgDebugAllowTestKeys, false, "allow test keys (UNSAFE)")
	_ = debugAllowTestKeysFlag.MarkHidden(CfgDebugAllowTestKeys)
	_ = viper.BindPFlags(debugAllowTestKeysFlag)

	debugRlimitFlag.Uint64(CfgDebugRlimit, 0, "set RLIMIT_NOFILE")
	_ = debugRlimitFlag.MarkHidden(CfgDebugRlimit)
	_ = viper.BindPFlags(debugRlimitFlag)

	RootFlags.StringVar(&cfgFile, cfgConfigFile, "", "config file")
	RootFlags.String(CfgDataDir, "", "data directory")
	_ = viper.BindPFlags(RootFlags)

	RootFlags.AddFlagSet(loggingFlags)
	RootFlags.AddFlagSet(debugAllowTestKeysFlag)
	RootFlags.AddFlagSet(debugRlimitFlag)
	RootFlags.AddFlagSet(flags.DebugDontBlameOasisFlag)
}

// InitConfig initializes the command configuration.
//
// WARNING: This is exposed for the benefit of tests and the interface
// is not guaranteed to be stable.
func InitConfig() {
	if cfgFile != "" {
		// Read the config file if one is provided, otherwise
		// it is assumed that the combination of default values,
		// command line flags and env vars is sufficient.
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			EarlyLogAndExit(err)
		}
	}

	dataDir := viper.GetString(CfgDataDir)

	// Force the DataDir to be an absolute path.
	if dataDir != "" {
		var err error
		dataDir, err = filepath.Abs(dataDir)
		if err != nil {
			EarlyLogAndExit(err)
		}
	}

	// The command line flag values may be missing, but may be specified
	// from other sources, write back to the common flag vars for
	// convenience.
	//
	// Note: This is only for flags that are common across all
	// sub-commands, so excludes things such as the gRPC/Metrics/etc
	// configuration.
	viper.Set(CfgDataDir, dataDir)
}

func initDataDir() error {
	dataDir := viper.GetString(CfgDataDir)
	if dataDir == "" {
		return nil
	}
	return common.Mkdir(dataDir)
}

func normalizePath(f string) string {
	if !filepath.IsAbs(f) {
		dataDir := viper.GetString(CfgDataDir)
		f = filepath.Join(dataDir, f)
		return filepath.Clean(f)
	}
	return f
}

func initPublicKeyBlacklist() error {
	allowTestKeys := flags.DebugDontBlameOasis() && viper.GetBool(CfgDebugAllowTestKeys)
	signature.BuildPublicKeyBlacklist(allowTestKeys)
	ias.BuildMrSignerBlacklist(allowTestKeys)
	return nil
}

func initRlimit() error {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		// Log, but don't return the error, this is only used for testing
		// and to warn the user if it's set too low.
		rootLog.Warn("failed to query RLIMIT_NOFILE",
			"err", err,
		)
		return nil
	}

	if rlim.Cur <= badDefaultRlimit {
		rootLog.Warn("the node user has a very low RLIMIT_NOFILE, consider increasing",
			"cur", rlim.Cur,
			"max", rlim.Max,
		)
	}

	desiredLimit := viper.GetUint64(CfgDebugRlimit)
	if !flags.DebugDontBlameOasis() || desiredLimit == 0 {
		return nil
	}

	rlim.Cur = desiredLimit
	return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
}

// GetOutputWriter will create a file if the config string is set,
// and otherwise return os.Stdout.
func GetOutputWriter(cmd *cobra.Command, cfg string) (io.WriteCloser, bool, error) {
	f, _ := cmd.Flags().GetString(cfg)
	if f == "" {
		return os.Stdout, false, nil
	}

	w, err := os.Create(f)
	return w, true, err
}

// GetInputReader will open a file if the config string is set,
// and otherwise return os.Stdin.
func GetInputReader(cmd *cobra.Command, cfg string) (io.ReadCloser, bool, error) {
	f, _ := cmd.Flags().GetString(cfg)
	if f == "" {
		return os.Stdin, false, nil
	}

	r, err := os.Open(f)
	return r, true, err
}

// LoadEntity loads the entity and it's signer.
func LoadEntity(signerBackend string, entityDir string) (*entity.Entity, signature.Signer, error) {
	if flags.DebugTestEntity() {
		return entity.TestEntity()
	}

	factory, err := SignerFactory(signerBackend, entityDir)
	if err != nil {
		return nil, nil, err
	}

	return entity.Load(entityDir, factory)
}
