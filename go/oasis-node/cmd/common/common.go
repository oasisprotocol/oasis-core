// Package common implements common oasis-node command options and utilities.
package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
)

const (
	CfgConfigFile = "config"

	// CfgDebugAllowTestKeys is the command line flag to enable the debug test
	// keys.
	CfgDebugAllowTestKeys = "debug.allow_test_keys"
	// CfgDebugAllowDebugEnclaves is the command line flag to enable debug enclaves.
	CfgDebugAllowDebugEnclaves = "debug.allow_debug_enclaves"
	// CfgDebugTCBLaxVerify is the command line flag to enable lax verification of PCS TCB statuses.
	CfgDebugTCBLaxVerify = "debug.tcb_lax_verify"
	// CfgDebugSkipQuoteVerify is the command line flag to skip PCS quote verification.
	CfgDebugSkipQuoteVerify = "debug.skip_quote_verify"

	// RequiredRlimit is the minimum required RLIMIT_NOFILE as too low of a
	// limit can cause problems with BadgerDB.
	RequiredRlimit = 50_000

	// InternalSocketName is the default name of the internal gRPC socket.
	InternalSocketName = "internal.sock"
)

var (
	cfgFile string

	rootLog = logging.GetLogger("oasis-node")

	debugFlags = flag.NewFlagSet("", flag.ContinueOnError)

	// RootFlags has the flags that are common across all commands.
	RootFlags = flag.NewFlagSet("", flag.ContinueOnError)

	isNodeCmd bool
)

// DataDir returns the data directory iff one is set.
func DataDir() string {
	return config.GlobalConfig.Common.DataDir
}

// InternalSocketPath returns the path to the node's internal unix socket.
func InternalSocketPath() string {
	if config.GlobalConfig.Common.InternalSocketPath != "" {
		return config.GlobalConfig.Common.InternalSocketPath
	}
	return filepath.Join(DataDir(), InternalSocketName)
}

// IsNodeCmd returns true iff the current command is the ekiden node.
func IsNodeCmd() bool {
	return isNodeCmd
}

// SetIsNodeCmd sets the IsNodeCmd flag.
func SetIsNodeCmd(v bool) {
	isNodeCmd = v
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
		initDebugEnclaves,
		initDebugTCBLaxVerify,
		initDebugSkipQuoteVerify,
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
	debugFlags.Bool(CfgDebugAllowTestKeys, false, "allow test keys (UNSAFE)")
	debugFlags.Bool(CfgDebugAllowDebugEnclaves, false, "allow debug enclaves (UNSAFE)")
	debugFlags.Bool(CfgDebugTCBLaxVerify, false, "allow lax verification of TCB statuses (UNSAFE)")
	debugFlags.Bool(CfgDebugSkipQuoteVerify, false, "skip quote verification (UNSAFE)")
	_ = debugFlags.MarkHidden(CfgDebugAllowTestKeys)
	_ = debugFlags.MarkHidden(CfgDebugAllowDebugEnclaves)
	_ = debugFlags.MarkHidden(CfgDebugTCBLaxVerify)
	_ = debugFlags.MarkHidden(CfgDebugSkipQuoteVerify)
	_ = viper.BindPFlags(debugFlags)

	RootFlags.StringVar(&cfgFile, CfgConfigFile, "", "config file")
	_ = viper.BindPFlags(RootFlags)

	RootFlags.AddFlagSet(debugFlags)
	RootFlags.AddFlagSet(flags.DebugDontBlameOasisFlag)
}

// InitConfig initializes the global configuration.
func InitConfig() {
	if cfgFile != "" {
		// Read the config file if one is provided, otherwise
		// it is assumed that the combination of default values,
		// command line flags and env vars is sufficient.
		if err := config.InitConfig(cfgFile); err != nil {
			EarlyLogAndExit(err)
		}
	}

	// Force the DataDir to be an absolute path.
	dataDir := config.GlobalConfig.Common.DataDir
	if dataDir != "" {
		var err error
		dataDir, err = filepath.Abs(dataDir)
		if err != nil {
			EarlyLogAndExit(err)
		}

		config.GlobalConfig.Common.DataDir = dataDir
	}
}

func initDataDir() error {
	dataDir := config.GlobalConfig.Common.DataDir
	if dataDir == "" {
		return nil
	}
	return common.Mkdir(dataDir)
}

func normalizePath(f string) string {
	if !filepath.IsAbs(f) {
		dataDir := config.GlobalConfig.Common.DataDir
		f = filepath.Join(dataDir, f)
		return filepath.Clean(f)
	}
	return f
}

func initPublicKeyBlacklist() error {
	allowTestKeys := flags.DebugDontBlameOasis() && viper.GetBool(CfgDebugAllowTestKeys)
	signature.BuildPublicKeyBlacklist(allowTestKeys)
	ias.BuildMrSignerBlacklist(allowTestKeys)
	pcs.BuildMrSignerBlacklist(allowTestKeys)
	return nil
}

func initDebugEnclaves() error {
	if flags.DebugDontBlameOasis() && viper.GetBool(CfgDebugAllowDebugEnclaves) {
		rootLog.Warn("`debug.allow_debug_enclaves` set, enclaves in debug mode will be allowed")
		ias.SetAllowDebugEnclaves()
		pcs.SetAllowDebugEnclaves()
	}
	return nil
}

func initDebugTCBLaxVerify() error {
	if flags.DebugDontBlameOasis() && viper.GetBool(CfgDebugTCBLaxVerify) {
		rootLog.Warn("`debug.tcb_lax_verify` set, TCB lax verification will be done")
		pcs.SetUnsafeLaxVerify()
	}
	return nil
}

func initDebugSkipQuoteVerify() error {
	if flags.DebugDontBlameOasis() && viper.GetBool(CfgDebugSkipQuoteVerify) {
		rootLog.Warn("`debug.skip_quote_verify` set, PCS quotes will NOT be verified")
		pcs.SetSkipVerify()
	}
	return nil
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

// LoadEntitySigner loads the entity and its signer.
func LoadEntitySigner() (*entity.Entity, signature.Signer, error) {
	if flags.DebugTestEntity() {
		return entity.TestEntity()
	}
	entityDir, err := cmdSigner.CLIDirOrPwd()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve entity dir: %w", err)
	}

	factory, err := cmdSigner.NewFactory(cmdSigner.Backend(), entityDir, signature.SignerEntity)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signer factory for %s: %w", cmdSigner.Backend(), err)
	}

	return entity.Load(entityDir, factory)
}

// ExportEntity creates an empty entity from the public key of the signer
// generated with the specified backend, and writes it to a file in entityDir.
func ExportEntity(signerBackend, entityDir string) error {
	factory, err := cmdSigner.NewFactory(signerBackend, entityDir, signature.SignerEntity)
	if err != nil {
		return err
	}
	signer, err := factory.Load(signature.SignerEntity)
	if err != nil {
		return err
	}

	_, err = entity.GenerateWithSigner(entityDir, signer, nil)
	return err
}

// GetUserConfirmation displays the prompt, and scans the input for
// the user's confirmation, until the user either explicitly confirms
// or rejects the prompt.
//
// Note: If standard input is not a tty, this will omit displaying
// the prompt, and assume the user entered yes.
func GetUserConfirmation(prompt string) bool {
	if !Isatty(os.Stdin.Fd()) {
		return true
	}

	fmt.Printf("%s", prompt)

	var response string
	for {
		_, err := fmt.Scanln(&response)
		if err != nil && err.Error() != "unexpected newline" {
			rootLog.Error("Error reading from line", "err", err)
			continue
		}

		switch strings.ToLower(response) {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			fmt.Printf("Unrecognized response: '%s'. Please, type (y)es or (n)o: ", response)
		}
	}
}

// SetBasicVersionTemplate sets a basic custom version template for the given
// cobra command that shows the version of Oasis Core and the Go toolchain.
func SetBasicVersionTemplate(cmd *cobra.Command) {
	cobra.AddTemplateFunc("toolchain", func() any { return version.Toolchain })

	cmd.SetVersionTemplate(`Software version: {{.Version}}
Go toolchain version: {{ toolchain }}
`)
}

// IsNotRootOrAllowed returns if the current user is allowed to run a node,
// and if the effective user id is elevated or not.
func IsNotRootOrAllowed() (canRun bool, isRoot bool) {
	isRoot = os.Geteuid() == 0
	canRun = !isRoot || flags.DebugAllowRoot()
	return
}
