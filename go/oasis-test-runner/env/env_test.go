package env

import (
	"encoding/json"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestParameterFlagSet_Clone(t *testing.T) {
	fs1 := NewParameterFlagSet("fs1", pflag.ExitOnError)
	require.Equal(t, "fs1", fs1.name)
	require.Equal(t, pflag.ExitOnError, fs1.errorHandling)

	// Add and/or set flags.
	fs1.String("flag1", "defaultvalue1", "usage1")
	fs1.String("flag2", "defaultvalue2", "usage2")
	fs1.Int("flag3", 42, "usage3")
	require.NoError(t, fs1.Set("flag1", "value1"))
	fs1f1, _ := fs1.GetString("flag1")
	fs1f2, _ := fs1.GetString("flag2")
	fs1f3, _ := fs1.GetInt("flag3")
	require.Equal(t, "value1", fs1f1)
	require.Equal(t, "defaultvalue2", fs1f2)
	require.Equal(t, 42, fs1f3)

	// Check if flagset is correctly cloned.
	fs2 := fs1.Clone()
	require.Equal(t, fs1.name, fs2.name)
	require.Equal(t, fs1.errorHandling, fs2.errorHandling)
	fs1f1, _ = fs1.GetString("flag1")
	fs1f2, _ = fs1.GetString("flag2")
	fs1f3, _ = fs1.GetInt("flag3")
	fs2f1, _ := fs2.GetString("flag1")
	fs2f2, _ := fs2.GetString("flag2")
	fs2f3, _ := fs2.GetInt("flag3")
	require.Equal(t, fs1f1, fs2f1)
	require.Equal(t, fs1f2, fs2f2)
	require.Equal(t, fs1f3, fs2f3)

	// Check whether changing fs2 values leaves fs1 values intact.
	require.NoError(t, fs2.Set("flag1", "value_new1"))
	require.NoError(t, fs2.Set("flag2", "value_new2"))
	require.NoError(t, fs2.Set("flag3", "43"))
	fs1f1, _ = fs1.GetString("flag1")
	fs1f2, _ = fs1.GetString("flag2")
	fs1f3, _ = fs1.GetInt("flag3")
	fs2f1, _ = fs2.GetString("flag1")
	fs2f2, _ = fs2.GetString("flag2")
	fs2f3, _ = fs2.GetInt("flag3")
	require.Equal(t, "value1", fs1f1)
	require.Equal(t, "defaultvalue2", fs1f2)
	require.Equal(t, 42, fs1f3)
	require.Equal(t, "value_new1", fs2f1)
	require.Equal(t, "value_new2", fs2f2)
	require.Equal(t, 43, fs2f3)
}

func TestParameterFlagSet_MarshalJSON(t *testing.T) {
	fs := NewParameterFlagSet("fs", pflag.ExitOnError)
	fs.String("flag1", "defaultvalue1", "usage1")
	fs.String("flag2", "defaultvalue2", "usage2")
	require.NoError(t, fs.Set("flag1", "value1"))

	data, err := json.Marshal(fs)
	require.NoError(t, err)

	var fsNew map[string]string
	err = json.Unmarshal(data, &fsNew)
	require.NoError(t, err)

	require.Equal(t, "value1", fsNew["flag1"])
	require.Equal(t, "defaultvalue2", fsNew["flag2"])
}
