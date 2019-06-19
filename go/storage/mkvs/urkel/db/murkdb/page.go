package murkdb

import (
	"fmt"
	"unsafe"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

// invalidOffset is an invalid offset pointer value.
const invalidOffset = 0xffffffffffffffff

// maxAllocSize is the size used when creating array pointers.
const maxAllocSize = 0x7FFFFFFF

// pageHeaderSize is the size of the page header.
const pageHeaderSize = int(unsafe.Offsetof(((*page)(nil)).ptr))

// internalPageNodeSize is the size of the internal page node.
const internalPageNodeSize = int(unsafe.Sizeof(internalPageNode{}))

// leafPageNodeSize is the size of the leaf page node (without the stored value).
const leafPageNodeSize = int(unsafe.Sizeof(leafPageNode{}))

const (
	// pageKindMKVS is a page kind used for storing the Merklized Key-Value Store.
	pageKindMKVS = 0x01

	// pageNodeKindInternal is a page node kind used for storing internal MKVS nodes.
	pageNodeKindInternal = 0x01
	// pageNodeKindLeaf is a page node kind used for storing leaf MKVS nodes.
	pageNodeKindLeaf = 0x02
)

type page struct {
	// id is the page identifier.
	id uint64
	// kind is the type of a page.
	kind uint16
	// overflow is the number of overflow pages (pages following this page
	// to hold any values that are too big to hold in a page).
	overflow uint32

	// Page contains kind-specific elements from here on. The ptr element
	// is used to get the address of the first element and does not store
	// an actual pointer.

	ptr uintptr
}

func (p *page) String() string {
	switch p.kind {
	case pageKindMKVS:
		return "mkvs"
	default:
		return fmt.Sprintf("[malformed: %02x]", p.kind)
	}
}

func (p *page) internalNodeAt(offset uintptr) *internalPageNode {
	start := unsafe.Pointer(&p.ptr)
	return (*internalPageNode)(unsafe.Pointer(uintptr(start) + offset))
}

func (p *page) leafNodeAt(offset uintptr) *leafPageNode {
	start := unsafe.Pointer(&p.ptr)
	return (*leafPageNode)(unsafe.Pointer(uintptr(start) + offset))
}

// pageNodeHeader is a common header for all page nodes.
type pageNodeHeader struct {
	// kind is the kind of a page node.
	kind uint8
}

func (n *pageNodeHeader) String() string {
	switch n.kind {
	case pageNodeKindInternal:
		return "internal"
	case pageNodeKindLeaf:
		return "leaf"
	default:
		return fmt.Sprintf("[malformed: %02x]", n.kind)
	}
}

func (n *pageNodeHeader) leafNode() *leafPageNode {
	if n.kind != pageNodeKindLeaf {
		return nil
	}
	return (*leafPageNode)(unsafe.Pointer(n))
}

func (n *pageNodeHeader) internalNode() *internalPageNode {
	if n.kind != pageNodeKindInternal {
		return nil
	}
	return (*internalPageNode)(unsafe.Pointer(n))
}

// leafPageNode is a leaf node stored in a page.
//
// Keys and values are stored directly after all the leaf nodes in a page.
type leafPageNode struct {
	pageNodeHeader

	// offset is an offset to the key/value location.
	offset uint32
	// keySize is the length of the key.
	keySize uint32
	// valueSize is the length of the value.
	valueSize uint32
}

func (n *leafPageNode) key() []byte {
	buf := (*[maxAllocSize]byte)(unsafe.Pointer(n))
	return (*[maxAllocSize]byte)(unsafe.Pointer(&buf[n.offset]))[:n.keySize:n.keySize]
}

func (n *leafPageNode) value() []byte {
	buf := (*[maxAllocSize]byte)(unsafe.Pointer(n))
	return (*[maxAllocSize]byte)(unsafe.Pointer(&buf[n.offset+n.keySize]))[:n.valueSize:n.valueSize]
}

// internalPageNode is an internal node stored in a page.
type internalPageNode struct {
	pageNodeHeader

	// leftHash is the Merkle hash of the left node pointed to.
	leftHash hash.Hash
	// leftOffset is the location of the left node pointed to.
	leftOffset uint64

	// rightHash is the Merkle hash of the right node pointed to.
	rightHash hash.Hash
	// rightOffset is the location of the right node pointed to.
	rightOffset uint64
}
