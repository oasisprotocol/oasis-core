package murkdb

import (
	_ "fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var (
	ErrCorruptedDb = errors.New("murkdb: corrupted database")
)

const (
	// maxMapSize represents the largest supported mmap size.
	maxMapSize = 0xFFFFFFFFFFFF // 256TB
	// maxMapStep is the largest step that can be taken when remapping.
	maxMapStep = 0x40000000 // 1GB
)

type treeDB struct {
	// file is a handle to the underlying database file.
	file *os.File

	// data is the read-only memory-mapped data reference.
	//
	// Any writes into this section will trigger a SIGSEGV.
	//
	// NOTE: This is subject to remapping so references to this slice may
	//       become corrupted. If the reference is going to outlive holding
	//       the remapLock then it should either be copied or kept as an
	//       offset into this slice instead.
	data []byte
	// dataSize is the size of the memory mapping.
	dataSize int
	// pageSize is the size of the page.
	pageSize int
	// remapLock is the mutex protecting the data during remapping.
	remapLock sync.RWMutex
}

func openTreeDB(filename string) (*treeDB, error) {
	t := &treeDB{
		pageSize: os.Getpagesize(),
	}

	// Open the database file or create it if it doesn't exist.
	var err error
	if t.file, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE, fileMode); err != nil {
		_ = t.close()
		return nil, err
	}

	// TODO: Lock the file so only one process can have it open at the same time.

	// Memory map the database file.
	if err := t.remap(0); err != nil {
		_ = t.close()
		return nil, err
	}

	return t, nil
}

// remap mmaps the database file into memory, unmapping an existing mapping first.
func (t *treeDB) remap(minSize int) error {
	t.remapLock.Lock()
	defer t.remapLock.Unlock()

	info, err := t.file.Stat()
	if err != nil {
		return errors.Wrap(err, "murkdb: remap stat failed")
	}

	// Ensure the size is at least the minimum size.
	var size = int(info.Size())
	if size < minSize {
		size = minSize
	}
	size, err = t.mmapSize(size)
	if err != nil {
		return err
	}

	// Unmap existing data before continuing.
	if err := t.unmapLocked(); err != nil {
		return err
	}

	// Map the data file to memory as read-only.
	b, err := unix.Mmap(int(t.file.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return errors.Wrap(err, "murkdb: mmap failed")
	}

	// Advise the kernel that the mmap is accessed randomly.
	err = unix.Madvise(b, unix.MADV_RANDOM)
	if err != nil && err != unix.ENOSYS {
		// Ignore not implemented error in kernel because it still works.
		return errors.Wrap(err, "murkdb: madvise failed")
	}

	t.data = b
	t.dataSize = size
	return nil
}

// mmapSize determines the appropriate size for the mmap given the current size
// of the database. The minimum size is 32KB and doubles until it reaches 1GB.
// Returns an error if the new mmap size is greater than the max allowed.
func (t *treeDB) mmapSize(size int) (int, error) {
	// Double the size from 32KB until 1GB.
	for i := uint(15); i <= 30; i++ {
		if size <= 1<<i {
			return 1 << i, nil
		}
	}

	// Verify the requested size is not above the maximum allowed.
	if size > maxMapSize {
		return 0, errors.New("murkdb: mmap size too large")
	}

	// If larger than 1GB then grow by 1GB at a time.
	sz := int64(size)
	if remainder := sz % int64(maxMapStep); remainder > 0 {
		sz += int64(maxMapStep) - remainder
	}

	// Ensure that the mmap size is a multiple of the page size.
	// This should always be true since we're incrementing in MBs.
	pageSize := int64(t.pageSize)
	if (sz % pageSize) != 0 {
		sz = ((sz / pageSize) + 1) * pageSize
	}

	// If we've exceeded the max size then only grow up to the max size.
	if sz > maxMapSize {
		sz = maxMapSize
	}

	return int(sz), nil
}

// unmapLocked unmaps the memory-mapped database file.
//
// The caller must hold remapLock before calling this method.
func (t *treeDB) unmapLocked() error {
	if t.data == nil {
		return nil
	}

	// Unmap using the original byte slice.
	err := unix.Munmap(t.data)
	t.data = nil
	t.dataSize = 0
	return errors.Wrap(err, "murkdb: munmap failed")
}

func pointerToOffset(ptr *internal.Pointer) uint64 {
	if ptr == nil {
		return invalidOffset
	}

	offset, ok := ptr.DBInternal.(uint64)
	if !ok {
		panic("murkdb: node should be persisted but does not seem to be")
	}
	return offset
}

// write writes a page to disk.
func (t *treeDB) write(page *page) error {
	offset := int64(page.id) * int64(t.pageSize)
	size := int64(page.overflow+1) * int64(t.pageSize)

	// Write out page in "max allocation" sized chunks.
	ptr := (*[maxAllocSize]byte)(unsafe.Pointer(page))
	for {
		// Limit our write to our max allocation size.
		sz := size
		if sz > maxAllocSize-1 {
			sz = maxAllocSize - 1
		}

		// Write chunk to disk.
		buf := ptr[:sz]
		if _, err := t.file.WriteAt(buf, offset); err != nil {
			return err
		}

		// Exit inner for loop if we've written all the chunks.
		size -= sz
		if size == 0 {
			break
		}

		// Otherwise move offset forward and move pointer to next chunk.
		offset += int64(sz)
		ptr = (*[maxAllocSize]byte)(unsafe.Pointer(&ptr[sz]))
	}

	// TODO: Put small page buffers to page pool.

	return nil
}

func (t *treeDB) dereference(offset uint64) (*pageNodeHeader, error) {
	if offset == invalidOffset {
		return nil, errors.New("murkdb: dereference of nil node")
	}

	pgOffset := offset - (offset % uint64(t.pageSize))
	page := (*page)(unsafe.Pointer(&t.data[pgOffset]))
	if page.kind != pageKindMKVS {
		return nil, errors.New("murkdb: dereference of non-mkvs page")
	}

	return (*pageNodeHeader)(unsafe.Pointer(&t.data[offset])), nil
}

func (t *treeDB) close() error {
	t.remapLock.Lock()
	defer t.remapLock.Unlock()

	// Unmap read-only mapping.
	if err := t.unmapLocked(); err != nil {
		return err
	}

	// Close file handle.
	if t.file != nil {
		// TODO: funlock.
		if err := t.file.Close(); err != nil {
			return errors.Wrap(err, "murkdb: failed to close database file")
		}

		t.file = nil
	}

	return nil
}
