//go:build gofuzz
// +build gofuzz

// Package fuzz provides some common utilities useful for fuzzing other packages.
package fuzz

import (
	"context"
	"fmt"
	"reflect"

	"github.com/thepudds/fzgo/randparam"
)

// NewFilledInstance fills the given object with random values from the given blob.
func NewFilledInstance(data []byte, typ interface{}) interface{} {
	if typ == nil {
		return nil
	}

	fuzzer := randparam.NewFuzzer(data)
	obj := reflect.New(reflect.TypeOf(typ)).Interface()
	fuzzer.Fuzz(obj)

	return obj
}

// InterfaceFuzzer is a helper class for fuzzing methods in structs or interfaces.
type InterfaceFuzzer struct {
	instance interface{}

	typeObject reflect.Type
	valObject  reflect.Value

	methodList []int

	typeOverrides map[string]func() interface{}
}

// OverrideType registers a custom callback for creating instances of a given type.
func (i *InterfaceFuzzer) OverrideType(typeName string, factory func() interface{}) {
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

	fuzzer := randparam.NewFuzzer(blob[1:])

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

// Method returns the method object associated with the fuzzer's index-th method for this instance.
func (i *InterfaceFuzzer) Method(method int) reflect.Method {
	return i.typeObject.Method(i.methodList[method])
}

// IgnoreMethodNames makes the interface fuzzer skip the named methods.
func (i *InterfaceFuzzer) IgnoreMethodNames(names []string) {
	var newMethodList []int

FilterLoop:
	for _, index := range i.methodList {
		name := i.typeObject.Method(index).Name
		for _, ignoreName := range names {
			if name == ignoreName {
				continue FilterLoop
			}
		}
		newMethodList = append(newMethodList, index)
	}

	i.methodList = newMethodList
}

// NewInterfaceFuzzer creates a new InterfaceFuzzer for the given instance.
func NewInterfaceFuzzer(instance interface{}) *InterfaceFuzzer {
	val := reflect.ValueOf(instance)
	ret := &InterfaceFuzzer{
		instance:   instance,
		typeObject: val.Type(),
		valObject:  val,
		typeOverrides: map[string]func() interface{}{
			"context.Context": func() interface{} {
				return context.Background()
			},
		},
	}

	for meth := 0; meth < val.NumMethod(); meth++ {
		ret.methodList = append(ret.methodList, meth)
	}

	return ret
}
