//go:build !windows

package process

import "syscall"

// Implements Process.
func (n *naked) Kill() {
	_ = n.cmd.Process.Kill()
	<-n.waitCh

	// Some environments (lolDocker) do not have something that
	// reaps zombie processes by default.  Kill the process group
	// as well.
	_ = syscall.Kill(-n.cmd.Process.Pid, syscall.SIGKILL)
}
