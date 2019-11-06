package persistent

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPersistent(t *testing.T) {
	dir, err := ioutil.TempDir("", "oasis-core-unittests")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	common, err := NewCommonStore(dir)
	assert.NoError(t, err, "NewCommonStore")

	svc, err := common.GetServiceStore("persistent_test")
	assert.NoError(t, err, "GetServiceStore")

	key := []byte("foo")
	val := "bar"

	err = svc.PutCBOR(key, &val)
	assert.NoError(t, err, "PutCBOR")

	var valOut string
	err = svc.GetCBOR(key, &valOut)
	assert.NoError(t, err, "GetCBOR")

	nonexistentKey := []byte("baz")
	err = svc.GetCBOR(nonexistentKey, &valOut)
	assert.Equal(t, ErrNotFound, err, "GetCBOR(nonexistent)")
}
