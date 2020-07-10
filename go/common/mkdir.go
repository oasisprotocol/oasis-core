package common

import (
	"fmt"
	"os"
	"syscall"
)

// Mkdir creates a directory iff it does not exist, and otherwise
// ensures that the filesystem permissions are sufficiently restrictive.
func Mkdir(d string) error {
	const permDir = os.FileMode(0o700)

	fi, err := os.Lstat(d)
	if err != nil {
		// Iff the directory does not exist, create it.
		if os.IsNotExist(err) {
			if err = os.MkdirAll(d, permDir); err == nil {
				return nil
			}
		}
		return err
	}

	// Ensure that the existing path is a directory, with sufficiently
	// restrictive permissions.
	fm := fi.Mode()
	if !fm.IsDir() {
		return fmt.Errorf("common/Mkdir: path '%s' is not a directory", d)
	}
	if fm.Perm() != permDir {
		return fmt.Errorf("common/Mkdir: path '%s' has invalid permissions: %v. Expected permissions: %v", d, fm.Perm(), permDir)
	}
	if fs, ok := fi.Sys().(*syscall.Stat_t); ok {
		euid := os.Geteuid()
		if euid != int(fs.Uid) {
			return fmt.Errorf("common/Mkdir: path '%s' has invalid owner: %d. Expected owner: %d", d, fs.Uid, euid)
		}
	}

	return nil
}
