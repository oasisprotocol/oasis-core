//go:build windows
// +build windows

package process

// Implements Process.
func (n *naked) Kill() {
	_ = n.cmd.Process.Kill()
	<-n.waitCh
}
