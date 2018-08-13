package common

// Cloneable interface allows a type to be copied.
type Cloneable interface {
	// Clone returns a copy of itself.
	Clone() Cloneable
}
