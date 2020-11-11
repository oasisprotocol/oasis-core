package crash

import (
	"sort"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const CrashPanicValue = "crash"

type testDeterministicRandomProvider struct {
	Value float64
}

func (r *testDeterministicRandomProvider) Float64() float64 {
	return r.Value
}

func newDeterministicRandomProvider(initialValue float64) *testDeterministicRandomProvider {
	return &testDeterministicRandomProvider{
		Value: initialValue,
	}
}

func testCrashMethod() {
	panic(CrashPanicValue)
}

func newTestCrasher(crashPoints map[string]float64, options CrasherOptions) *Crasher {
	crasher := New(options)

	var crashMap sync.Map
	for k, v := range crashPoints {
		crashMap.Store(k, v)
	}

	// The default CrashMethod is not something that we can `recover` from so
	// it's not possible to use in tests. We replace it here with a panic that
	// returns a specific value.
	crasher.CrashMethod = testCrashMethod
	crasher.CrashPointConfig = &crashMap
	return crasher
}

func TestCrashHere(t *testing.T) {
	testForceEnable = true
	defer func() {
		testForceEnable = false
	}()

	deterministicRandomProvider := newDeterministicRandomProvider(0.4)
	crasher := newTestCrasher(map[string]float64{
		"succeed": 0.0,
		"fail":    1.0,
		"half":    0.5,
	}, CrasherOptions{
		// Override the random function to return deterministic values.
		Rand: deterministicRandomProvider,
	})

	testFail := func() {
		crasher.Here("fail")
	}
	testSucceed := func() {
		crasher.Here("succeed")
	}
	testFailureCrashPointNotDefined := func() {
		crasher.Here("undefined")
	}
	testHalf := func() {
		crasher.Here("half")
	}

	assert.PanicsWithValue(t, CrashPanicValue, testFail, "should panic if probability is 1.0")
	assert.NotPanics(t, testSucceed, "should not panic if probability is 0.0")
	assert.Panics(t, testFailureCrashPointNotDefined, "should panic if crash point is unknown")
	assert.PanicsWithValue(t, CrashPanicValue, testHalf, "should panic if probability is 0.5 and random returns 0.4")

	// Override the random function to force 0.6 to be returned.
	deterministicRandomProvider.Value = 0.6
	assert.NotPanics(t, testHalf, "should not panic if probability is 0.5 and random returns 0.6")
}

func TestCrashPointRegistrationAndConfig(t *testing.T) {
	testForceEnable = true
	defer func() {
		testForceEnable = false
	}()

	crasher := newTestCrasher(map[string]float64{}, CrasherOptions{})
	crasher.RegisterCrashPoints("point1", "point2")
	crasher.RegisterCrashPoints("point3")

	registeredCrashPoints := crasher.ListRegisteredCrashPoints()
	sort.Strings(registeredCrashPoints)

	assert.Equal(t, registeredCrashPoints, []string{"point1", "point2", "point3"}, "should have 2 registered crash points")

	crasher.Config(map[string]float64{
		"point1": 1.0,
		"point2": 0.66,
		"point3": 0.8,
	})

	p1, ok := crasher.CrashPointConfig.Load("point1")
	assert.True(t, ok, "should set point1 correctly")
	assert.Equal(t, 1.0, p1, "should set point1 correctly")
	p2, ok := crasher.CrashPointConfig.Load("point2")
	assert.True(t, ok, "should set point2 correctly")
	assert.Equal(t, 0.66, p2, "should set point2 correctly")
	p3, ok := crasher.CrashPointConfig.Load("point3")
	assert.True(t, ok, "should set point3 correctly")
	assert.Equal(t, 0.8, p3, "should set point3 correctly")

	configShouldFail := func() {
		// This should fail because point4 is not registered.
		crasher.Config(map[string]float64{
			"point4": 0.3,
		})
	}
	assert.Panics(t, configShouldFail, "should panic if point4 is unregistered")
}

func TestGlobalCrashPointRegistrationViaFlags(t *testing.T) {
	testForceEnable = true
	defer func() {
		testForceEnable = false
	}()

	// Set non-zero default probability.
	viper.Set(CfgDefaultCrashPointProbability, 0.1)

	// Register test crash point.
	RegisterCrashPoints("test.global.point")
	RegisterCrashPoints("test.global.point2")

	viper.Set(defaultCLIPrefix+"."+"test.global.point2", 0.5)

	// Load values from flags.
	LoadViperArgValues()

	p1, ok := crashGlobal.CrashPointConfig.Load("test.global.point")
	assert.True(t, ok, "should set test point correctly")
	assert.Equal(t, 0.1, p1, "should set default point probability")

	p2, ok := crashGlobal.CrashPointConfig.Load("test.global.point2")
	assert.True(t, ok, "should set test point correctly")
	assert.Equal(t, 0.5, p2, "should set configured point probability")
}
