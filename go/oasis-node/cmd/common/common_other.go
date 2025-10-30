//go:build !windows

package common

import (
	"fmt"
	"syscall"

	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

func initRlimit() error {
	// Suppress this for tooling, as it likely does not matter.
	if !IsNodeCmd() {
		return nil
	}

	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return fmt.Errorf("failed to query RLIMIT_NOFILE: %w", err)
	}

	desiredLimit := config.GlobalConfig.Common.Debug.Rlimit
	if flags.DebugDontBlameOasis() && desiredLimit > 0 && desiredLimit != rlim.Cur {
		rlim.Cur = desiredLimit
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
			return fmt.Errorf("failed setting RLIMIT_NOFILE: %w", err)
		}
	}

	if rlim.Cur < RequiredRlimit {
		return fmt.Errorf("too low RLIMIT_NOFILE, current: %d required: %d", rlim.Cur, RequiredRlimit)
	}

	return nil
}

func Umask(mask int) int {
	return syscall.Umask(mask)
}
