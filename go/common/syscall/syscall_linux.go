// Package syscall defines OS-specific syscall parameters.
package syscall

import "syscall"

// IoctlTermiosGetAttr is the ioctl that implements termios tcgetattr.
const IoctlTermiosGetAttr = syscall.TCGETS

// CmdAttrs is the SysProcAttr that will ensure graceful cleanup (on Linux).
var CmdAttrs = &syscall.SysProcAttr{
	Pdeathsig: syscall.SIGKILL,
}
