package env

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
)

const (
	cfgBaseDir          = "basedir"
	cfgBaseDirNoCleanup = "basedir.no_cleanup"
	cfgBaseDirNoTempDir = "basedir.no_temp_dir"
)

var (
	rootDir Dir

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Dir is a directory for test data and output.
type Dir struct {
	dir       string
	noCleanup bool
}

// String returns the string representation (path) of the Dir.
func (d *Dir) String() string {
	return d.dir
}

// Init initializes the Dir, creating it iff it does not yet exist.
func (d *Dir) Init(cmd *cobra.Command) error {
	if d.dir != "" {
		return fmt.Errorf("env: base directory already initialized")
	}

	d.dir = viper.GetString(cfgBaseDir)
	d.noCleanup = viper.GetBool(cfgBaseDirNoCleanup)

	if viper.GetBool(cfgBaseDirNoTempDir) {
		// If we don't create a temporary directory, don't clean up.
		d.noCleanup = true
	} else {
		// Create a temporary directory using a prefix derived from the
		// command's `Use` field.
		var err error
		splitUse := strings.Split(cmd.Use, " ")
		if d.dir, err = ioutil.TempDir(d.dir, splitUse[0]); err != nil {
			return fmt.Errorf("env: failed to create default base directory: %w", err)
		}
	}

	return nil
}

// SetNoCleanup enables/disables the removal of the Dir on Cleanup.
func (d *Dir) SetNoCleanup(v bool) {
	d.noCleanup = v
}

// NewSubDir creates a new subdirectory under a Dir, and returns the
// sub-directory's Dir.
func (d *Dir) NewSubDir(subDirName string) (*Dir, error) {
	dirName := filepath.Join(d.String(), subDirName)
	if err := common.Mkdir(dirName); err != nil {
		return nil, fmt.Errorf("env: failed to create sub-directory: %w", err)
	}

	return &Dir{
		dir:       dirName,
		noCleanup: d.noCleanup,
	}, nil
}

// NewLogWriter creates a log file under a Dir with the provided name.
func (d *Dir) NewLogWriter(name string) (io.WriteCloser, error) {
	fn := filepath.Join(d.String(), name)
	w, err := os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("env: failed to create file for append: %w", err)
	}

	return w, nil
}

// Cleanup cleans up the Dir.
func (d *Dir) Cleanup() {
	if d.dir == "" || d.noCleanup {
		return
	}

	_ = os.RemoveAll(d.dir)
	d.dir = ""
}

// GetRootDir returns the global root Dir instance.
//
// Warning: This is not guaranteed to be valid till after `Dir.Init` is
// called.  Use of this routine from outside `oasis-test-runner/cmd` is
// strongly discouraged.
func GetRootDir() *Dir {
	return &rootDir
}

func init() {
	Flags.String(cfgBaseDir, "", "test base directory")
	Flags.Bool(cfgBaseDirNoCleanup, false, "do not cleanup test base directory")
	Flags.Bool(cfgBaseDirNoTempDir, false, "do not create a temp directory inside base directory")

	_ = viper.BindPFlags(Flags)
}
