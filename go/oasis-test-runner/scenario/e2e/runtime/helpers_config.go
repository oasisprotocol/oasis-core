package runtime

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// TEEHardware returns the configured TEE hardware.
func (sc *Scenario) TEEHardware() (node.TEEHardware, error) {
	teeStr, _ := sc.Flags.GetString(cfgTEEHardware)
	var tee node.TEEHardware
	if err := tee.FromString(teeStr); err != nil {
		return node.TEEHardwareInvalid, err
	}
	return tee, nil
}

// BuildTargetDirs returns the configured build and target directories.
func (sc *Scenario) BuildTargetDirs() (string, string, error) {
	buildDir, _ := sc.Flags.GetString(cfgRuntimeSourceDir)
	targetDir, _ := sc.Flags.GetString(cfgRuntimeTargetDir)
	if buildDir == "" || targetDir == "" {
		return "", "", fmt.Errorf("runtime build dir and/or target dir not configured")
	}
	return buildDir, targetDir, nil
}
