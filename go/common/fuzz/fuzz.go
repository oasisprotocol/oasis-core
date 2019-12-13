// +build gofuzz

// Package fuzz provides some common utilities useful for fuzzing other packages.
package fuzz

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"reflect"

	gofuzz "github.com/google/gofuzz"
)

var (
	_ rand.Source64 = (*Source)(nil)
)

// Source is a randomness source for the standard random generator.
type Source struct {
	Backing   []byte
	Exhausted int

	pos   int
	track bool

	traceback []byte
}

func (s *Source) Int63() int64 {
	return int64(s.Uint64()&((1<<63)-1))
}

func (s *Source) Seed(_ int64) {
	// Nothing to do here.
}

func (s *Source) Uint64() uint64 {
	if s.pos+8 > len(s.Backing) {
		s.Exhausted += 8
		r := rand.Uint64()
		if s.track {
			chunk := make([]byte, 8)
			binary.BigEndian.PutUint64(chunk[0:], r)
			s.traceback = append(s.traceback, chunk...)
		}
		return r
	}

	s.pos += 8
	return binary.BigEndian.Uint64(s.Backing[s.pos-8 : s.pos])
}

// GetTraceback returns the array of bytes returned from the random generator so far.
func (s *Source) GetTraceback() []byte {
	return s.traceback
}

// NewRandSource returns a new random source with the given backing array.
func NewRandSource(backing []byte) *Source {
	return &Source{
		Backing: backing,
	}
}

// NewTrackingRandSource returns a new random source that keeps track of the bytes returned.
func NewTrackingRandSource() *Source {
	return &Source{
		Backing: []byte{},
		track:   true,
	}
}

// NewFilledInstance fills the given object with random values from the given blob.
func NewFilledInstance(data []byte, typ interface{}) (interface{}, bool) {
	if typ == nil {
		return nil, true
	}

	source := NewRandSource(data)
	fuzzer := gofuzz.New()
	fuzzer = fuzzer.RandSource(source)

	obj := reflect.New(reflect.TypeOf(typ)).Interface()

	fuzzer.Fuzz(obj)

	return obj, source.Exhausted == 0
}

// MakeSampleBlob creates and returns a sample blob of bytes for filling the given object.
func MakeSampleBlob(typ interface{}) []byte {
	if typ == nil {
		return []byte{}
	}

	source := NewTrackingRandSource()
	fuzzer := gofuzz.New()
	fuzzer = fuzzer.RandSource(source)

	obj := reflect.New(reflect.TypeOf(typ)).Interface()

	fuzzer.Fuzz(obj)

	return source.GetTraceback()
}

// InterfaceFuzzer is a helper class for fuzzing methods in structs or interfaces.
type InterfaceFuzzer struct {
	instance interface{}

	typeObject reflect.Type
	valObject  reflect.Value

	methodList []int

	typeOverrides map[string]func()interface{}
}

// OverrideType registers a custom callback for creating instances of a given type.
func (i *InterfaceFuzzer) OverrideType(typeName string, factory func()interface{}) {
	i.typeOverrides[typeName] = factory
}

// DispatchBlob constructs a method call with arguments from the given blob and dispatches it.
func (i *InterfaceFuzzer) DispatchBlob(blob []byte) ([]reflect.Value, bool) {
	if len(blob) < 1 {
		return nil, false
	}

	meth := int(blob[0])
	if meth >= len(i.methodList) {
		return nil, false
	}
	meth = i.methodList[meth]
	if meth >= i.typeObject.NumMethod() {
		return nil, false
	}
	methType := i.typeObject.Method(meth).Type
	method := i.valObject.Method(meth)

	source := NewRandSource(blob[1:])
	fuzzer := gofuzz.New()
	fuzzer = fuzzer.RandSource(source).NilChance(0)

	in := []reflect.Value{}

	for arg := 1; arg < methType.NumIn(); arg++ {
		inType := methType.In(arg)
		inTypeName := fmt.Sprintf("%s.%s", inType.PkgPath(), inType.Name())

		var val reflect.Value
		if factory, ok := i.typeOverrides[inTypeName]; ok {
			inst := factory()
			val = reflect.ValueOf(inst)
		} else {
			val = reflect.New(inType)
			if val.Interface() != nil {
				fuzzer.Fuzz(val.Interface())
			}
			val = val.Elem()
		}
		in = append(in, val)
	}

	return method.Call(in), true
}

// MakeSampleBlobs returns an array of sample blobs for all methods in the interface.
func (i *InterfaceFuzzer) MakeSampleBlobs() [][]byte {
	blobList := [][]byte{}
	for seq, meth := range i.methodList {
		source := NewTrackingRandSource()
		fuzzer := gofuzz.New()
		fuzzer = fuzzer.RandSource(source).NilChance(0)

		method := i.typeObject.Method(meth)
		blob := []byte{byte(seq)}
		for arg := 1; arg < method.Type.NumIn(); arg++ {
			inType := method.Type.In(arg)
			inTypeName := fmt.Sprintf("%s.%s", inType.PkgPath(), inType.Name())
			if _, ok := i.typeOverrides[inTypeName]; !ok {
				newValue := reflect.New(inType)
				if newValue.Interface() != nil {
					fuzzer.Fuzz(newValue.Interface())
				}
			}
		}

		blob = append(blob, source.GetTraceback()...)
		blobList = append(blobList, blob)
	}

	return blobList
}

// Method returns the method object associated with the fuzzer's index-th method for this instance.
func (i *InterfaceFuzzer) Method(method int) reflect.Method {
	return i.typeObject.Method(i.methodList[method])
}

// IgnoreMethodNames makes the interface fuzzer skip the named methods.
func (i *InterfaceFuzzer) IgnoreMethodNames(names []string) {
	for _, name := range names {
		for listIndex, methIndex := range i.methodList {
			if i.typeObject.Method(methIndex).Name == name {
				i.methodList = append(i.methodList[:listIndex], i.methodList[listIndex+1:]...)
				break
			}
		}
	}
}

// NewInterfaceFuzzer creates a new InterfaceFuzzer for the given instance.
func NewInterfaceFuzzer(instance interface{}) *InterfaceFuzzer {
	val := reflect.ValueOf(instance)
	ret := &InterfaceFuzzer{
		instance:      instance,
		typeObject:    val.Type(),
		valObject:     val,
		typeOverrides: map[string]func()interface{}{
			"context.Context": func()interface{}{
				return context.Background()
			},
		},
	}

	for meth := 0; meth < val.NumMethod(); meth++ {
		ret.methodList = append(ret.methodList, meth)
	}

	return ret
}
