// Package debug implements various debugging utilities.
package debug

//go:noescape
func debugTrap()

// Trap crashes the current process with `SIGTRAP`.
func Trap() {
	debugTrap()
}
