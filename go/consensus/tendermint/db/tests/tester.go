// Package tests is a collection of tendermint DB backend tests.
package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
	dbm "github.com/tendermint/tm-db"
)

// TestTendermintDB tests the provided tendermint database.
func TestTendermintDB(t *testing.T, db dbm.DB) {
	// Run the sub-tests.
	t.Run("BasicOps", func(t *testing.T) { testBasicOps(t, db) })
	t.Run("BatchOps", func(t *testing.T) { testBatchOps(t, db) })
	t.Run("Iterator", func(t *testing.T) { testIterator(t, db) })
	t.Run("Misc", func(t *testing.T) { testMisc(t, db) })
}

func testBasicOps(t *testing.T, db dbm.DB) {
	require := require.New(t)

	// Non-existent keys, don't exist.
	exists, err := db.Has([]byte("non-existent"))
	require.NoError(err, "Has(non-existent)")
	require.False(exists, "Has(non-existent)")
	v, err := db.Get([]byte("non-existent"))
	require.NoError(err, "Get(non-existent)")
	require.Nil(v, "Get(non-existent")

	// The nil key should work, as an empty byte slice.
	v = []byte("Can I has nil key?")
	err = db.Set(nil, v)
	require.NoError(err, "Set(nil)")
	exists, err = db.Has(nil)
	require.NoError(err, "Has(nil)")
	require.True(exists, "Has(nil)")
	exists, err = db.Has([]byte{})
	require.NoError(err, "Has([]byte{})")
	require.True(exists, "Has([]byte{})")
	vv, err := db.Get(nil)
	require.NoError(err, "Get(nil)")
	require.EqualValues(v, vv, "Get(nil)")
	vv, err = db.Get([]byte{})
	require.NoError(err, "Get([]byte{})")
	require.EqualValues(v, vv, "Get([]byte{})")
	err = db.Delete(nil)
	require.NoError(err, "Delete(nil)")
	exists, err = db.Has(nil)
	require.NoError(err, "Has(nil), post Delete()")
	require.False(exists, "Has(nil), post Delete()")

	// An actual key should also work.
	key, value := []byte("Yog-Sothoth"), []byte("is the key and guardian of the gate.")
	err = db.Set(key, value)
	require.NoError(err, "Set(k,v)")
	exists, err = db.Has(key)
	require.NoError(err, "Has(k)")
	require.True(exists, "Has(k)")
	vv, err = db.Get(key)
	require.NoError(err, "Get(k)")
	require.EqualValues(value, vv, "Get(k)")
	err = db.Delete(key)
	require.NoError(err, "Delete(k)")
	exists, err = db.Has(key)
	require.NoError(err, "Has(k), post Delete()")
	require.False(exists, "Has(k), post Delete()")

	// The sync equivalents to Set/Delete() should work.
	err = db.SetSync(key, value)
	require.NoError(err, "SetSync(k,v)")
	exists, err = db.Has(key)
	require.NoError(err, "Has(k) - SetSync()")
	require.True(exists, "Has(k) - SetSync()")
	vv, err = db.Get(key)
	require.NoError(err, "Get(k) - SetSync()")
	require.EqualValues(value, vv, "Get(k) - SetSync()")
	err = db.DeleteSync(key)
	require.NoError(err, "DeleteSync(k)")
	exists, err = db.Has(key)
	require.NoError(err, "Has(k), post DeleteSync()")
	require.False(exists, "Has(k), post DeleteSync()")
}

func testBatchOps(t *testing.T, db dbm.DB) {
	require := require.New(t)

	toDeleteKey := []byte("to-delete")
	err := db.Set(toDeleteKey, []byte("some value"))
	require.NoError(err, "Set(toDelete)")

	// Build and execute the batch.
	k1, k2 := []byte("key1"), []byte("key2")
	v1, v2 := []byte("value1"), []byte("value2")
	batch := db.NewBatch()
	err = batch.Set(k1, v1)
	require.NoError(err, "batch.Set(k1, v1)")
	err = batch.Set(k2, v2)
	require.NoError(err, "batch.Set(k2, v2)")
	err = batch.Delete(toDeleteKey)
	require.NoError(err, "batch.Delete(to-delete)")
	err = batch.Write()
	require.NoError(err, "batch.Write()")

	vv, err := db.Get(k1)
	require.NoError(err, "Get(k1)")
	require.EqualValues(v1, vv, "Get(k1)")
	vv, err = db.Get(k2)
	require.NoError(err, "Get(k2)")
	require.EqualValues(v2, vv, "Get(k2)")
	exists, err := db.Has(toDeleteKey)
	require.NoError(err, "Has(deleted)")
	require.False(exists, "Has(deleted)")

	// Build and execute the clean-up batch.
	batch = db.NewBatch()
	err = batch.Delete(k1)
	require.NoError(err, "batch.Delete(k1)")
	err = batch.Delete(k2)
	require.NoError(err, "batch.Delete(k2)")
	err = batch.WriteSync()
	require.NoError(err, "batch.WriteSync()")
	exists, err = db.Has(k1)
	require.NoError(err, "Has(k1), post WriteSync")
	require.False(exists, "Has(k1), post WriteSync")
	exists, err = db.Has(k2)
	require.NoError(err, "Has(k2), post WriteSync")
	require.False(exists, "Has(k2), post WriteSync")
}

func testIterator(t *testing.T, db dbm.DB) {
	// Note: Weird failures will happen if the database isn't empty
	// due to prior tests not running to completion.

	require := require.New(t)

	entries := []struct {
		key, value []byte
	}{
		{[]byte{}, []byte("nil")},
		{[]byte("a"), []byte("a")},
		{[]byte("ab"), []byte("ab")},
		{[]byte("ac"), []byte("ac")},
		{[]byte("b"), []byte("b")},
		{[]byte("c"), []byte("c")},
	}

	const (
		subStart = 1 // `a`
		subEnd   = 4 // `b`
	)

	// Populate the database.
	batch := db.NewBatch()
	for _, ent := range entries {
		err := batch.Set(ent.key, ent.value)
		require.NoError(err, "batch.Set(%s)", ent.key)
	}
	err := batch.Write()
	require.NoError(err, "batch.Write()")

	// Traverse forward (entire range).
	fwdIter, err := db.Iterator(nil, nil)
	require.NoError(err, "db.Iterator(nil, nil)")
	for i, ent := range entries {
		require.True(fwdIter.Valid(), "Fwd[%d]: Valid()", i)
		require.EqualValues(ent.key, fwdIter.Key(), "Fwd[%d]: Key()", i)
		require.EqualValues(ent.value, fwdIter.Value(), "Fwd[%d]: Value()", i)
		fwdIter.Next()
	}
	require.False(fwdIter.Valid(), "Fwd[tail]: Valid()")

	// Ensure the accessors for an invalid iterator panic.
	require.Panics(func() { fwdIter.Key() }, "Key(), invalid iterator")
	require.Panics(func() { fwdIter.Value() }, "Value(), invalid iterator")
	require.Panics(func() { fwdIter.Value() }, "Next(), invalid iterator")

	fwdIter.Close()

	// Traverse forward (subset).
	fwdSubIter, err := db.Iterator([]byte("a"), []byte("b"))
	require.NoError(err, "db.Iterator(a, b)")
	for i := subStart; i < subEnd; i++ {
		ent := entries[i]
		require.True(fwdSubIter.Valid(), "Fwd[%d]: Valid(), skip", i)
		require.EqualValues(ent.key, fwdSubIter.Key(), "Fwd[%d]: Key(), skip", i)
		require.EqualValues(ent.value, fwdSubIter.Value(), "Fwd[%d]: Value(), skip", i)
		fwdSubIter.Next()
	}
	require.False(fwdSubIter.Valid(), "Fwd[tail]: Valid(), skip")

	start, end := fwdSubIter.Domain() // Might as well do this here.
	require.EqualValues([]byte("a"), start, "Domain() start")
	require.EqualValues([]byte("b"), end, "Domain() end")
	fwdSubIter.Close()

	// Traverse backward (entire range).
	revIter, err := db.ReverseIterator(nil, nil)
	require.NoError(err, "db.ReverseIterator(nil, nil)")
	for i := len(entries) - 1; i >= 0; i-- {
		ent := entries[i]
		require.True(revIter.Valid(), "Rev[%d]: Valid()", i)
		require.EqualValues(ent.key, revIter.Key(), "Rev[%d]: Key()", i)
		require.EqualValues(ent.value, revIter.Value(), "Rev[%d]: Value()", i)
		revIter.Next()
	}
	require.False(revIter.Valid(), "Rev[tail]: Valid()")
	revIter.Close()

	// Traverse backward (subset).
	revSubIter, err := db.ReverseIterator([]byte("a"), []byte("b"))
	require.NoError(err, "db.ReverseIterator(a, b)")
	for i := subEnd - 1; i >= subStart; i-- { // End is exclusive (v0.27.0)
		ent := entries[i]
		require.True(revSubIter.Valid(), "Rev[%d]: Valid(), skip", i)
		require.EqualValues(ent.key, revSubIter.Key(), "Rev[%d]: Key(), skip", i)
		require.EqualValues(ent.value, revSubIter.Value(), "Rev[%d]: Value(), skip", i)
		revSubIter.Next()
	}
	require.False(revSubIter.Valid(), "Rev[tail]: Valid(), skip")

	// Traverse backward (subset, inexact end).
	revSubIEIter, err := db.ReverseIterator([]byte("a"), []byte("ad"))
	require.NoError(err, "db.ReverseIterator(a, ad)")
	for i := subEnd - 1; i >= subStart; i-- { // End is exclusive (v0.27.0)
		ent := entries[i]
		require.True(revSubIEIter.Valid(), "RevSubIE[%d]: Valid(), skip", i)
		require.EqualValues(ent.key, revSubIEIter.Key(), "RevSubIE[%d]: Key(), skip", i)
		require.EqualValues(ent.value, revSubIEIter.Value(), "RevSubIE[%d]: Value(), skip", i)
		revSubIEIter.Next()
	}
	require.False(revSubIEIter.Valid(), "RevSubIE[tail]: Valid(), skip")

	// Deliberately leave revSubIter un-Close()ed, to test that the
	// Next() call that invalidated the iterator cleans everything up.
	//
	// Note: This is only possible with the BoltDB backend, which
	// doesn't exist anymore.
	stats := db.Stats()
	if stats["database.type"] == "BoltDB" {
		require.Equal("0", stats["database.tx.read.open"], "Dangling transactions???")
	}
}

func testMisc(t *testing.T, db dbm.DB) {
	require := require.New(t)

	stats := db.Stats()
	t.Logf("DB Stats(): %+v", stats)

	err := db.Print() // Produces no output, though it does log at debug level.
	require.NoError(err, "Print()")
}
