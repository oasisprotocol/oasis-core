package cli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"

	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdRegRt "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/runtime"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// RegistryHelpers contains the oasis-node registry CLI helpers.
type RegistryHelpers struct {
	*helpersBase
}

// GenerateRegisterRuntimeTx is a wrapper for "registry runtime gen_register" subcommand.
func (r *RegistryHelpers) GenerateRegisterRuntimeTx(
	baseDir string,
	runtime registry.Runtime,
	nonce uint64,
	txPath string,
) error {
	r.logger.Info("generating register runtime tx")

	// Save runtime descriptor into a temp file.
	rtDescPath := filepath.Join(baseDir, fmt.Sprintf("registry_runtime_register_descriptor-%s.json", runtime.ID))
	rtDescStr, _ := json.Marshal(runtime)
	if err := ioutil.WriteFile(rtDescPath, rtDescStr, 0o600); err != nil {
		return fmt.Errorf("failed to write runtime descriptor to file: %w", err)
	}

	args := []string{
		"registry", "runtime", "gen_register",
		"--" + cmdRegRt.CfgRuntimeDescriptor, rtDescPath,
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(0), // TODO: Make fee configurable.
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(10000), // TODO: Make fee configurable.
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + cmdCommon.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugTestEntity,
		"--" + flags.CfgGenesisFile, r.cfg.GenesisFile,
	}

	if out, err := r.runSubCommandWithOutput("registry-runtime-gen_register", args); err != nil {
		return fmt.Errorf("failed to run 'registry runtime gen_register': error: %w output: %s", err, out.String())
	}
	return nil
}
