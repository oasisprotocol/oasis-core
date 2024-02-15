package pathbadger

import (
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
)

var (
	// keyFormat is the namespace for the pathbadger database key formats.
	keyFormat = keyformat.NewNamespace("pathbadger")

	// metadataKeyFmt is the key format for metadata.
	//
	// Value is CBOR-serialized metadata.
	metadataKeyFmt = keyFormat.New(0x00)

	// writeLogKeyFmt is the key format for write logs: (version, dst root, src root).
	//
	// Value is CBOR-serialized internalWriteLog.
	writeLogKeyFmt = keyFormat.New(0x01, uint64(0), &api.TypedHash{}, &api.TypedHash{})

	// rootUpdatedNodesKeyFmt is the key format for the pending updated nodes for the given root
	// that need to be removed only in case the given root is not among the finalized roots. The
	// key format is (version, root).
	//
	// Value is CBOR-serialized []updatedNode.
	rootUpdatedNodesKeyFmt = keyFormat.New(0x02, uint64(0), &api.TypedHash{})

	// rootNodeKeyFmt is the key format for root nodes: (version, typed node hash).
	//
	// Value is the serialized root node.
	rootNodeKeyFmt = keyFormat.New(0x03, uint64(0), &api.TypedHash{})

	// finalizedNodeKeyFmt is the key format for finalized nodes and pending nodes at zero seqNo.
	// The latter is done optimistically so in the common case where there are no forks, no copying
	// of nodes from pending to finalized is needed. The key format is (type, path).
	//
	// Value is the serialized node.
	finalizedNodeKeyFmt = keyFormat.New(0x04, byte(0), []byte{})

	// pendingNodeKeyFmt is the key format for pending nodes at seqNo > 0 which will be discarded
	// after the version is finalized. In case a non-zero seqNo is finalized, these nodes will need
	// to first be copied over to the finalizedNode set during finalization. The key format is
	// (version, type, seqNo, path).
	//
	// Value is the serialized node.
	pendingNodeKeyFmt = keyFormat.New(0x05, uint64(0), byte(0), uint16(0), []byte{})

	// multipartRestoreNodeLogKeyFmt is the key format for the nodes inserted during a chunk
	// restore. Once a set of chunks is fully restored, these entries should be removed. If chunk
	// restoration is interrupted for any reason, the nodes associated with these keys should be
	// removed, along with these entries.
	//
	// Value is empty.
	multipartRestoreNodeLogKeyFmt = keyFormat.New(0x06, byte(0), []byte{})
)
