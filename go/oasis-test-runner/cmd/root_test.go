package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeParamSets(t *testing.T) {
	var zippedParams map[string][]string
	var expectedParamSets []map[string]string

	// Empty set.
	zippedParams = map[string][]string{}
	expectedParamSets = []map[string]string{}
	require.Equal(t, expectedParamSets, computeParamSets(zippedParams, map[string]string{}))

	// Single element, multiple parameters.
	zippedParams = map[string][]string{
		"testParam1": {"1"},
		"testParam2": {"a"},
		"testParam3": {"one"},
		"testParam4": {"ena"},
	}
	expectedParamSets = []map[string]string{
		{"testParam1": "1", "testParam2": "a", "testParam3": "one", "testParam4": "ena"},
	}
	require.Equal(t, expectedParamSets, computeParamSets(zippedParams, map[string]string{}))

	// Single element, empty string slice hack test.
	zippedParams = map[string][]string{
		"testParam1": {"1"},
		"testParam2": {},
	}
	expectedParamSets = []map[string]string{
		{"testParam1": "1", "testParam2": ""},
	}
	require.Equal(t, expectedParamSets, computeParamSets(zippedParams, map[string]string{}))

	// Combinations of two elements.
	zippedParams = map[string][]string{
		"testParam1": {"1", "2", "3"},
		"testParam2": {"a", "b"},
	}
	expectedParamSets = []map[string]string{
		{"testParam1": "1", "testParam2": "a"},
		{"testParam1": "1", "testParam2": "b"},
		{"testParam1": "2", "testParam2": "a"},
		{"testParam1": "2", "testParam2": "b"},
		{"testParam1": "3", "testParam2": "a"},
		{"testParam1": "3", "testParam2": "b"},
	}
	require.Equal(t, expectedParamSets, computeParamSets(zippedParams, map[string]string{}))

	// Duplicated elements - should not affect the outcome.
	zippedParams = map[string][]string{
		"testParam1": {"1", "1", "1"},
		"testParam2": {"a", "b"},
	}
	expectedParamSets = []map[string]string{
		{"testParam1": "1", "testParam2": "a"},
		{"testParam1": "1", "testParam2": "b"},
		{"testParam1": "1", "testParam2": "a"},
		{"testParam1": "1", "testParam2": "b"},
		{"testParam1": "1", "testParam2": "a"},
		{"testParam1": "1", "testParam2": "b"},
	}
	require.Equal(t, expectedParamSets, computeParamSets(zippedParams, map[string]string{}))
}

func TestGeneralizedScenarioName(t *testing.T) {
	var expectedNames []string

	expectedNames = []string{"e2e/runtime/abc/def", "e2e/runtime/abc", "e2e/runtime", "e2e"}
	require.Equal(t, expectedNames, generalizedScenarioName("e2e/runtime/abc/def"))

	expectedNames = []string{"e2e"}
	require.Equal(t, expectedNames, generalizedScenarioName("e2e"))

	expectedNames = []string{""}
	require.Equal(t, expectedNames, generalizedScenarioName(""))
}
