// Package bundle implements the bundle sub-commands.
package bundle

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
)

const (
	CfgRuntimeID            = "runtime.id"
	CfgRuntimeName          = "runtime.name"
	CfgRuntimeVersion       = "runtime.version"
	CfgRuntimeExecutable    = "runtime.executable"
	CfgRuntimeSGXExecutable = "runtime.sgx.executable"
	CfgRuntimeSGXSignature  = "runtime.sgx.signature"

	CfgRuntimeBundle = "runtime.bundle"

	execName    = "runtime.elf"
	sgxExecName = "runtime.sgx"
	sgxSigName  = "runtime.sgx.sig"
)

var (
	bundleCmd = &cobra.Command{
		Use:   "bundle",
		Short: "manipulate runtime bundles",
	}

	initCmd = &cobra.Command{
		Use:   "init",
		Short: "create a runtime bundle",
		RunE:  doInit,
	}

	infoCmd = &cobra.Command{
		Use:   "info",
		Short: "inspect a runtime bundle",
		RunE:  doInfo,
	}

	logger = logging.GetLogger("cmd/debug/bundle")
)

func doInit(cmd *cobra.Command, args []string) error {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// This creates runtimes with normalized internal filenames, for the
	// sake of consistency, though there is no reason why this needs to
	// be the case.
	var err error
	manifest := &bundle.Manifest{
		Name:       viper.GetString(CfgRuntimeName),
		Executable: execName,
	}
	if err = manifest.ID.UnmarshalText([]byte(viper.GetString(CfgRuntimeID))); err != nil {
		logger.Error("failed to parse runtime ID",
			"err", err,
		)
		return err
	}
	if manifest.Version, err = version.FromString(viper.GetString(CfgRuntimeVersion)); err != nil {
		logger.Error("failed to parse runtime version",
			"err", err,
		)
		return err
	}

	type runtimeFile struct {
		fn, descr, dst string
	}
	wantFiles := []runtimeFile{
		{
			fn:    viper.GetString(CfgRuntimeExecutable),
			descr: "runtime ELF binary",
			dst:   execName,
		},
	}
	if sgxExec := viper.GetString(CfgRuntimeSGXExecutable); sgxExec != "" {
		wantFiles = append(wantFiles, runtimeFile{
			fn:    viper.GetString(CfgRuntimeSGXExecutable),
			descr: "runtime SGX binary",
			dst:   sgxExecName,
		})
		manifest.SGX = &bundle.SGXMetadata{
			Executable: sgxExecName,
		}

		if sgxSig := viper.GetString(CfgRuntimeSGXSignature); sgxSig != "" {
			wantFiles = append(wantFiles, runtimeFile{
				fn:    viper.GetString(CfgRuntimeSGXExecutable),
				descr: "runtime SGX signature",
				dst:   sgxSigName,
			})
			manifest.SGX.Signature = sgxSigName
		}
	}
	bnd := &bundle.Bundle{
		Manifest: manifest,
	}
	for _, v := range wantFiles {
		if v.fn == "" {
			logger.Error("missing runtime asset",
				"descr", v.descr,
			)
			return err
		}
		var b []byte
		if b, err = os.ReadFile(v.fn); err != nil {
			logger.Error("failed to load runtime asset",
				"err", err,
				"descr", v.descr,
			)
			return err
		}
		_ = bnd.Add(v.dst, b)
	}

	dstFn := viper.GetString(CfgRuntimeBundle)
	if dstFn == "" {
		logger.Error("missing runtime bundle name")
		return err
	}
	if err = bnd.Write(dstFn); err != nil {
		logger.Error("failed to write runtime bundle",
			"err", err,
		)
		return err
	}

	return nil
}

func doInfo(cmd *cobra.Command, args []string) error {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	fn := viper.GetString(CfgRuntimeBundle)
	bnd, err := bundle.Open(fn)
	if err != nil {
		logger.Error("failed to open bundle",
			"err", err,
			"file_name", fn,
		)
		return err
	}

	b, err := json.MarshalIndent(bnd.Manifest, "", "  ")
	if err != nil {
		logger.Error("failed to reserialize manifest",
			"err", err,
		)
		return err
	}

	fmt.Println(string(b))

	return nil
}

// Register registers the bundle sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	commonFlags := flag.NewFlagSet("", flag.ContinueOnError)
	commonFlags.String(CfgRuntimeBundle, "runtime.orc", "path to runtime bundle")
	_ = viper.BindPFlags(commonFlags)

	initFlags := flag.NewFlagSet("", flag.ContinueOnError)
	initFlags.String(CfgRuntimeID, "", "runtime ID (Base16-encoded)")
	initFlags.String(CfgRuntimeName, "", "runtime name (optional)")
	initFlags.String(CfgRuntimeVersion, "0.0.0", "runtime version")
	initFlags.String(CfgRuntimeExecutable, "runtime.bin", "path to runtime ELF binary")
	initFlags.String(CfgRuntimeSGXExecutable, "", "path to runtime SGX binary")
	initFlags.String(CfgRuntimeSGXSignature, "", "path to runtime SGX signature")
	_ = viper.BindPFlags(initFlags)
	initCmd.Flags().AddFlagSet(initFlags)

	for _, cmd := range []*cobra.Command{
		initCmd,
		infoCmd,
	} {
		cmd.Flags().AddFlagSet(commonFlags)
		bundleCmd.AddCommand(cmd)
	}
	parentCmd.AddCommand(bundleCmd)
}
