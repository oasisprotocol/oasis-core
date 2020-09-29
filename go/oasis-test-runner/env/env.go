// Package env defines a scenario environment.
package env

import (
	"container/list"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	cmnSyscall "github.com/oasisprotocol/oasis-core/go/common/syscall"
)

// ErrEarlyTerm is the error passed over the error channel when a
// sub-process terminates prior to the Cleanup.
var ErrEarlyTerm = errors.New("env: sub-process exited early")

// CmdAttrs is the SysProcAttr that will ensure graceful cleanup (on Linux).
var CmdAttrs = cmnSyscall.CmdAttrs

// CleanupFn is the cleanup hook function prototype.
type CleanupFn func()

// ParameterFlagSet is a wrapper for flag.FlagSet to produce nicer JSON output.
type ParameterFlagSet struct {
	flag.FlagSet

	name          string
	errorHandling flag.ErrorHandling
}

// ScenarioInstanceInfo contains information of the current scenario run.
type ScenarioInstanceInfo struct {
	// Scenario is the name of the scenario.
	Scenario string `json:"scenario"`

	// Instance is the name of the scenario instance (e.g. oasis-test-runner123456).
	Instance string `json:"instance"`

	// ParameterSet is the parameter set the scenario was run with.
	ParameterSet *ParameterFlagSet `json:"parameter_set"`

	// Run is the number of the run.
	Run int `json:"run"`
}

// MarshalJSON outputs ParameterFlagSet as an ordinary JSON map.
func (pfs *ParameterFlagSet) MarshalJSON() ([]byte, error) {
	ps := make(map[string]string)
	pfs.VisitAll(func(f *flag.Flag) {
		ps[f.Name] = f.Value.String()
	})

	return json.Marshal(ps)
}

// Clone clones the parameter flagset.
//
// This function is usually called when cloning scenarios where we also want to clone existing
// parameter values.
func (pfs *ParameterFlagSet) Clone() *ParameterFlagSet {
	newPfs := NewParameterFlagSet(pfs.name, pfs.errorHandling)
	pfs.VisitAll(func(f *flag.Flag) {
		// Clone concrete members of Flag.
		fl := *f
		// Clone Value interface.
		fl.Value = reflect.New(reflect.TypeOf(fl.Value).Elem()).Interface().(flag.Value)
		// And actual flag value.
		_ = fl.Value.Set(f.Value.String())
		newPfs.AddFlag(&fl)
	})

	return newPfs
}

// NewParameterFlagSet returns new instance of ParameterFlagSet.
func NewParameterFlagSet(name string, eh flag.ErrorHandling) *ParameterFlagSet {
	return &ParameterFlagSet{
		FlagSet:       *flag.NewFlagSet(name, eh),
		name:          name,
		errorHandling: eh,
	}
}

// Env is a (nested) test environment.
type Env struct {
	name string

	parent     *Env
	parentElem *list.Element
	children   *list.List

	dir          *Dir
	scenarioInfo *ScenarioInstanceInfo
	cleanupFns   []CleanupFn
	cleanupCmds  []*cmdMonitor
	cleanupLock  sync.Mutex

	isInCleanup bool
}

// Name returns the environment name.
func (env *Env) Name() string {
	return env.name
}

// Dir returns the path to this test environment's data directory.
func (env *Env) Dir() string {
	return env.dir.String()
}

// CurrentDir returns the test environment's Dir.
func (env *Env) CurrentDir() *Dir {
	return env.dir
}

// NewSubDir creates a new subdirectory under the test environment.
func (env *Env) NewSubDir(subDirName string) (*Dir, error) {
	return env.dir.NewSubDir(subDirName)
}

// ScenarioInfo returns the scenario instance information.
func (env *Env) ScenarioInfo() *ScenarioInstanceInfo {
	return env.scenarioInfo
}

// AddOnCleanup adds a cleanup routine to be called during the environment's
// cleanup.  Routines will be called in reverse order that they were
// registered.
func (env *Env) AddOnCleanup(fn CleanupFn) {
	env.cleanupLock.Lock()
	defer env.cleanupLock.Unlock()

	env.cleanupFns = append([]CleanupFn{fn}, env.cleanupFns...)
}

// AddTermOnCleanup adds a process that will be terminated during the
// environment's cleanup, and will return a channel that will be
// closed (after an error is sent if applicable when the process
// terminates.
//
// Process will be terminated in the reverse order that they were
// registered.
//
// Processes are torn down *BEFORE* the on-cleanup hooks are run.
func (env *Env) AddTermOnCleanup(cmd *exec.Cmd) chan error {
	env.cleanupLock.Lock()
	defer env.cleanupLock.Unlock()

	m := &cmdMonitor{
		env:    env,
		cmd:    cmd,
		doneCh: make(chan error),
	}
	go m.wait()

	env.cleanupCmds = append([]*cmdMonitor{m}, env.cleanupCmds...)

	return m.doneCh
}

// Cleanup cleans up all of the environment's children, followed by the
// environment.
//
// Note: Unless the env is a root (top-level) environment, the directory
// will not be cleaned up.
func (env *Env) Cleanup() {
	env.cleanupLock.Lock()
	env.isInCleanup = true
	env.cleanupLock.Unlock()

	// Remove this from the parent's children list.
	if env.parentElem != nil {
		env.parent.children.Remove(env.parentElem)
	}

	for {
		childElem := env.children.Front()
		if childElem == nil {
			break
		}

		child := childElem.Value.(*Env)
		child.Cleanup()
	}

	// Tear down this environment's commands.
	for _, v := range env.cleanupCmds {
		v.termOrKill()
	}

	// Do the cleanup for this environment.
	for _, v := range env.cleanupFns {
		v()
	}

	// If this is the root, clean up the entire directory tree.
	if env.parent == nil {
		env.dir.Cleanup()
	}
}

// NewChild returns a new child test environment.
func (env *Env) NewChild(childName string, scInfo *ScenarioInstanceInfo) (*Env, error) {
	var parentDir *Dir
	if env.parent != nil {
		parentDir = env.parent.dir
	} else {
		parentDir = env.dir
	}

	subDir, err := parentDir.NewSubDir(childName)
	if err != nil {
		return nil, err
	}

	child := &Env{
		name:         childName,
		parent:       env,
		children:     list.New(),
		dir:          subDir,
		scenarioInfo: scInfo,
	}
	child.parentElem = env.children.PushBack(child)

	return child, nil
}

// WriteScenarioInfo dumps scenario instance parameter set to scenario_info.json
// file for debugging afterwards.
func (env *Env) WriteScenarioInfo() error {
	b, err := json.Marshal(env.scenarioInfo)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(filepath.Join(env.Dir(), "scenario_info.json"), b, 0o644); err != nil { // nolint: gosec
		return err
	}

	return nil
}

// New creates a new root test environment.
func New(dir *Dir) *Env {
	return &Env{
		children: list.New(),
		dir:      dir,
	}
}

type cmdMonitor struct {
	env    *Env
	cmd    *exec.Cmd
	doneCh chan error
}

func (m *cmdMonitor) wait() {
	defer close(m.doneCh)

	err := m.cmd.Wait()

	m.env.cleanupLock.Lock()
	defer m.env.cleanupLock.Unlock()
	if !m.env.isInCleanup {
		if err == nil {
			err = ErrEarlyTerm
		}
		m.doneCh <- err
	} else {
		m.doneCh <- nil
	}
}

func (m *cmdMonitor) termOrKill() {
	// Send a SIGTERM and wait a bit first to see if the process will
	// gracefully terminate.
	_ = m.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-time.After(5 * time.Second):
	case <-m.doneCh:
		return
	}

	// Send a SIGKILL and blow the process away.
	_ = m.cmd.Process.Kill()
	<-m.doneCh
}
