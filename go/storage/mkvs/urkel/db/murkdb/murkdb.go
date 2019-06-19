package murkdb

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
)

var _ api.NodeDB = (*murkNodeDB)(nil)

const (
	fileMode = 0600

	filenameMetaDB = "meta.bolt.db"
	filenameTreeDB = "tree.db"
)

type murkNodeDB struct {
	// meta is the BoltDB store used to hold metadata.
	meta *metaDB
	// tree is the mmapped database used to hold the tree nodes.
	tree *treeDB
}

// New creates a new MurkDB node database.
func New(dirname string) (api.NodeDB, error) {
	d := &murkNodeDB{}

	// Ensure the database directory exists.
	var err error
	if err = common.Mkdir(dirname); err != nil {
		return nil, errors.Wrap(err, "murkdb: failed to create database directory")
	}

	// Open tree database.
	if d.tree, err = openTreeDB(filepath.Join(dirname, filenameTreeDB)); err != nil {
		d.Close()
		return nil, errors.Wrap(err, "murkdb: failed to open tree db")
	}

	// Open metadata database.
	if d.meta, err = openMetaDB(filepath.Join(dirname, filenameMetaDB), d.tree); err != nil {
		return nil, errors.Wrap(err, "murkdb: failed to open metadata db")
	}

	return d, nil
}

func (d *murkNodeDB) GetNode(root hash.Hash, ptr *internal.Pointer) (internal.Node, error) {
	// Lookup root in index of roots.
	ri, err := d.meta.getRoot(root)
	if err != nil {
		return nil, errors.Wrap(err, "murkdb: failed to fetch root")
	}

	// Dereference pointer.
	if ptr.DBInternal == nil {
		// Pointer not retrieved from this database. This can only be the root
		// as otherwise we cannot resolve it.
		if !ptr.Hash.Equal(&root) {
			return nil, errors.New("murkdb: tried to dereference unknown pointer")
		}

		ptr.DBInternal = ri.offset
	}

	pn, err := d.tree.dereference(pointerToOffset(ptr))
	if err != nil {
		return nil, err
	}

	var node internal.Node
	switch pn.kind {
	case pageNodeKindInternal:
		intNode := pn.internalNode()

		node = &internal.InternalNode{
			Clean: true,
			Left: &internal.Pointer{
				Clean:      true,
				Hash:       intNode.leftHash,
				DBInternal: intNode.leftOffset,
			},
			Right: &internal.Pointer{
				Clean:      true,
				Hash:       intNode.rightHash,
				DBInternal: intNode.rightOffset,
			},
		}
	case pageNodeKindLeaf:
		leafNode := pn.leafNode()

		n := &internal.LeafNode{
			Clean: true,
			Value: &internal.Value{
				Clean: true,
				Value: make([]byte, leafNode.valueSize),
			},
		}
		copy(n.Key[:], leafNode.key())
		copy(n.Value.Value, leafNode.value())
		n.Value.UpdateHash()
		node = n
	default:
		return nil, ErrCorruptedDb
	}
	node.UpdateHash()

	return node, nil
}

func (d *murkNodeDB) GetValue(id hash.Hash) ([]byte, error) {
	panic("murkdb: value should always be bundled with leaf node")
}

func (d *murkNodeDB) Close() {
	if d.tree != nil {
		_ = d.tree.close()
		d.tree = nil
	}

	if d.meta != nil {
		_ = d.meta.close()
		d.meta = nil
	}
}
