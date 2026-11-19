package checkpoint

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

func encodeChunkEntries(t *testing.T, entries [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := cbor.NewEncoder(&buf)
	for _, entry := range entries {
		require.NoError(t, enc.Encode(entry))
	}
	return buf.Bytes()
}

func TestReadChunkProofLimits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		entries    [][]byte
		maxSize    int64
		maxEntries int
		wantErr    error
	}{
		{
			name:       "exact size and entry limits",
			entries:    [][]byte{nil, {}, {0x01}},
			maxSize:    4,
			maxEntries: 3,
		},
		{
			name:       "size exceeded at entry boundary",
			entries:    [][]byte{nil, nil, nil, nil},
			maxSize:    3,
			maxEntries: 10,
			wantErr:    errChunkTooLarge,
		},
		{
			name:       "null entries exceed aggregate count",
			entries:    [][]byte{nil, nil, nil, nil},
			maxSize:    32,
			maxEntries: 3,
			wantErr:    errChunkTooManyEntries,
		},
		{
			name:       "empty entries exceed aggregate count",
			entries:    [][]byte{{}, {}, {}, {}},
			maxSize:    32,
			maxEntries: 3,
			wantErr:    errChunkTooManyEntries,
		},
		{
			name:       "single large byte string",
			entries:    [][]byte{bytes.Repeat([]byte{0x01}, 1024)},
			maxSize:    32,
			maxEntries: 3,
			wantErr:    errChunkTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encodeChunkEntries(t, tc.entries)
			r := bytes.NewReader(encoded)
			p, err := readChunkProof(context.Background(), r, tc.maxSize, tc.maxEntries)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, p)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.entries, p.Entries)
			}
			require.LessOrEqual(t, int64(len(encoded)-r.Len()), tc.maxSize+1,
				"the decoder must not read past the decompression budget and overflow byte")
		})
	}
}

func TestReadChunkProofIncompleteEntries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		encoded []byte
		maxSize int64
		wantErr error
	}{
		{
			name:    "partial next header after exact byte limit",
			encoded: []byte{0xf6, 0x58},
			maxSize: 1,
			wantErr: errChunkTooLarge,
		},
		{
			name:    "partial header below byte limit",
			encoded: []byte{0xf6, 0x58},
			maxSize: 32,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "partial byte string below byte limit",
			encoded: []byte{0xf6, 0x43, 0x01},
			maxSize: 32,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name: "huge declared byte string bounded before allocation",
			// A byte string claiming 1 TiB, with enough data to exhaust the small budget.
			encoded: append([]byte{0x5b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
				bytes.Repeat([]byte{0x00}, 128)...),
			maxSize: 32,
			wantErr: errChunkTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(tc.encoded)
			p, err := readChunkProof(context.Background(), r, tc.maxSize, 10)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, p)
			require.LessOrEqual(t, int64(len(tc.encoded)-r.Len()), tc.maxSize+1)
		})
	}
}

func TestWriteChunkLimits(t *testing.T) {
	entries := [][]byte{nil, {}, {0x01}}
	encoded := encodeChunkEntries(t, entries)
	proof := &syncer.Proof{Entries: entries}
	for _, tc := range []struct {
		name       string
		maxSize    int64
		maxEntries int
		wantErr    error
	}{
		{"exact limits", int64(len(encoded)), len(entries), nil},
		{"size exceeded", int64(len(encoded)) - 1, len(entries), errChunkTooLarge},
		{"entry count exceeded", int64(len(encoded)), len(entries) - 1, errChunkTooManyEntries},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			digest, err := writeChunkWithLimits(proof, &buf, tc.maxSize, tc.maxEntries)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, hash.NewFromBytes(buf.Bytes()), digest)
			decoded, err := io.ReadAll(snappy.NewReader(&buf))
			require.NoError(t, err)
			require.Equal(t, encoded, decoded)
		})
	}
}

func TestRestoreChunkLimitIntegrity(t *testing.T) {
	// Null entries cost only one decompressed byte each, but each appended entry
	// would otherwise require a slice header in the proof.
	var buf bytes.Buffer
	sw := snappy.NewBufferedWriter(&buf)
	_, err := sw.Write(bytes.Repeat([]byte{0xf6}, maxChunkEntries+1))
	require.NoError(t, err)
	require.NoError(t, sw.Close())
	// Ensure the integrity check hashes even a trailing malformed compressed suffix
	// that the decoder never needs to read after the aggregate entry limit is hit.
	_, err = buf.Write([]byte{0x00, 0xff})
	require.NoError(t, err)
	encoded := buf.Bytes()

	for _, tc := range []struct {
		name    string
		digest  hash.Hash
		wantErr error
	}{
		{"matching digest", hash.NewFromBytes(encoded), ErrChunkProofVerificationFailed},
		{"incorrect digest", hash.NewFromBytes([]byte("different chunk")), ErrChunkCorrupted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(encoded)
			chunk := &ChunkMetadata{Digest: tc.digest}
			// A nil database makes accidental writes during rejection fail the test.
			err := restoreChunk(context.Background(), nil, chunk, r)
			require.ErrorIs(t, err, tc.wantErr)
			if tc.wantErr == ErrChunkProofVerificationFailed {
				require.Contains(t, err.Error(), errChunkTooManyEntries.Error())
			}
			require.Zero(t, r.Len(), "integrity verification must consume the compressed suffix")
		})
	}
}
