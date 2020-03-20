// +build gofuzz

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/fill2"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/fuzz2"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

func unmarshalValue(src io.Reader, v reflect.Value, indent int) error { // nolint: gocyclo
	if !v.CanSet() {
		fmt.Print("(unexported)")
		return nil
	}
	if fill, ok := v.Addr().Interface().(fill2.Fill); ok {
		if err := fill.Fill(src); err != nil {
			return fmt.Errorf("fill %s: %w", v.Type().Name(), err)
		}
		fmt.Printf("(fill '%s %v)", v.Type().Name(), fill)
		return nil
	}
	switch v.Type() {
	case reflect.TypeOf(time.Time{}):
		var sec int64
		if err := binary.Read(src, binary.LittleEndian, &sec); err != nil {
			return fmt.Errorf("read time sec: %w", err)
		}
		var nsec uint32
		if err := binary.Read(src, binary.LittleEndian, &nsec); err != nil {
			return fmt.Errorf("read time nsec: %w", err)
		}
		t := time.Unix(sec, int64(nsec))
		fmt.Printf("(time \"%v\")", t)
		v.Set(reflect.ValueOf(t))
		return nil
	}
	switch v.Kind() {
	case reflect.Bool:
		var b bool
		if err := binary.Read(src, binary.LittleEndian, &b); err != nil {
			return fmt.Errorf("read bool: %w", err)
		}
		fmt.Printf("(bool %v)", b)
		v.SetBool(b)
	case reflect.Int:
		var i int64
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read int: %w", err)
		}
		fmt.Printf("(int %v)", i)
		v.SetInt(i)
	case reflect.Int8:
		var i int8
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read int8: %w", err)
		}
		fmt.Printf("(int8 %d)", i)
		v.SetInt(int64(i))
	case reflect.Int16:
		var i int16
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read int16: %w", err)
		}
		fmt.Printf("(int16 %d)", i)
		v.SetInt(int64(i))
	case reflect.Int32:
		var i int32
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read int32: %w", err)
		}
		fmt.Printf("(int32 %d)", i)
		v.SetInt(int64(i))
	case reflect.Int64:
		var i int64
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read int64: %w", err)
		}
		fmt.Printf("(int64 %d)", i)
		v.SetInt(i)
	case reflect.Uint:
		var i uint64
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read uint: %w", err)
		}
		fmt.Printf("(uint %d)", i)
		v.SetUint(i)
	case reflect.Uint8:
		var i uint8
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read uint8: %w", err)
		}
		fmt.Printf("(uint8 %d)", i)
		v.SetUint(uint64(i))
	case reflect.Uint16:
		var i uint16
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read uint16: %w", err)
		}
		fmt.Printf("(uint16 %d)", i)
		v.SetUint(uint64(i))
	case reflect.Uint32:
		var i uint32
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read uint32: %w", err)
		}
		fmt.Printf("(uint32 %d)", i)
		v.SetUint(uint64(i))
	case reflect.Uint64:
		var i uint64
		if err := binary.Read(src, binary.LittleEndian, &i); err != nil {
			return fmt.Errorf("read uint64: %w", err)
		}
		fmt.Printf("(uint64 %d)", i)
		v.SetUint(i)
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			asBytes := v.Slice(0, v.Len()).Bytes()
			if _, err := src.Read(asBytes); err != nil {
				return fmt.Errorf("read bytearray (len %d): %w", v.Len(), err)
			}
			fmt.Printf("(bytearray \"%x\")", asBytes)
			return nil
		}
		fmt.Printf("(array\n%s", strings.Repeat("\t", indent))
		for i := 0; i < v.Len(); i++ {
			fmt.Print("\t(item ")
			if err := unmarshalValue(src, v.Index(i), indent+1); err != nil {
				return fmt.Errorf("array (len %d) index %d: %w", v.Len(), i, err)
			}
			fmt.Printf(")\n%s", strings.Repeat("\t", indent))
		}
		fmt.Print(")")
	case reflect.Map:
		var present bool
		if err := binary.Read(src, binary.LittleEndian, &present); err != nil {
			return fmt.Errorf("read map present: %w", err)
		}
		if !present {
			fmt.Print("(map nil)")
			v.Set(reflect.Zero(v.Type()))
		} else {
			fmt.Printf("(map\n%s", strings.Repeat("\t", indent))
			var ll uint8
			if err := binary.Read(src, binary.LittleEndian, &ll); err != nil {
				return fmt.Errorf("read map len: %w", err)
			}
			v.Set(reflect.MakeMap(v.Type()))
			for i := 0; i < int(ll); i++ {
				fmt.Print("\t(item ")
				kk := reflect.New(v.Type().Key()).Elem()
				if err := unmarshalValue(src, kk, indent+1); err != nil {
					return fmt.Errorf("map (len %d) index %d key: %w", ll, i, err)
				}
				fmt.Print(" ")
				vv := reflect.New(v.Type().Elem()).Elem()
				if err := unmarshalValue(src, vv, indent+1); err != nil {
					return fmt.Errorf("map (len %d) index %d (key %v) value: %w", ll, i, kk, err)
				}
				fmt.Printf(")\n%s", strings.Repeat("\t", indent))
				v.SetMapIndex(kk, vv)
			}
			fmt.Print(")")
		}
	case reflect.Ptr:
		var present bool
		if err := binary.Read(src, binary.LittleEndian, &present); err != nil {
			return fmt.Errorf("read ptr present: %w", err)
		}
		if !present {
			fmt.Print("(ptr nil)")
			v.Set(reflect.Zero(v.Type()))
		} else {
			v.Set(reflect.New(v.Type().Elem()))
			fmt.Print("(ptr ")
			if err := unmarshalValue(src, v.Elem(), indent); err != nil {
				return fmt.Errorf("ptr elem: %w", err)
			}
			fmt.Print(")")
		}
	case reflect.Slice:
		var present bool
		if err := binary.Read(src, binary.LittleEndian, &present); err != nil {
			return fmt.Errorf("read slice present: %w", err)
		}
		if !present {
			fmt.Print("(slice nil)")
			v.Set(reflect.Zero(v.Type()))
		} else {
			if v.Type().Elem().Kind() == reflect.Uint8 {
				var ll uint16
				if err := binary.Read(src, binary.LittleEndian, &ll); err != nil {
					return fmt.Errorf("read byteslice len: %w", err)
				}
				b := make([]byte, ll)
				if _, err := src.Read(b); err != nil {
					return fmt.Errorf("read byteslice (len %d): %w", ll, err)
				}
				fmt.Printf("(byteslice \"%x\")", b)
				v.Set(reflect.ValueOf(b))
				return nil
			}
			fmt.Printf("(slice\n%s", strings.Repeat("\t", indent))
			var ll uint8
			if err := binary.Read(src, binary.LittleEndian, &ll); err != nil {
				return fmt.Errorf("read slice len: %w", err)
			}
			v.Set(reflect.MakeSlice(v.Type(), int(ll), int(ll)))
			for i := 0; i < int(ll); i++ {
				fmt.Print("\t(item ")
				if err := unmarshalValue(src, v.Index(i), indent+1); err != nil {
					return fmt.Errorf("slice (len %d) index %d: %w", ll, i, err)
				}
				fmt.Printf(")\n%s", strings.Repeat("\t", indent))
			}
			fmt.Print(")")
		}
	case reflect.String:
		var ll uint8
		if err := binary.Read(src, binary.LittleEndian, &ll); err != nil {
			return fmt.Errorf("read string len: %w", err)
		}
		b := make([]byte, ll)
		if _, err := src.Read(b); err != nil {
			return fmt.Errorf("read string (len %d) bytes: %w", ll, err)
		}
		s := string(b)
		fmt.Printf("(string %+q)", s)
		v.SetString(s)
	case reflect.Struct:
		t := v.Type()
		fmt.Printf("(struct '%s\n%s", t.Name(), strings.Repeat("\t", indent))
		for i := 0; i < v.NumField(); i++ {
			tf := t.Field(i)
			if tf.Tag.Get("json") == "-" {
				fmt.Printf("\t(field '%s (omitted))\n%s", tf.Name, strings.Repeat("\t", indent))
				continue
			}
			fmt.Printf("\t(field '%s ", tf.Name)
			if err := unmarshalValue(src, v.Field(i), indent+1); err != nil {
				return fmt.Errorf("struct %s field %s: %w", t.Name(), tf.Name, err)
			}
			fmt.Printf(")\n%s", strings.Repeat("\t", indent))
		}
		fmt.Print(")")
	default:
		panic(fmt.Sprintf("not supported kind %d (line %d) %#v", v.Kind(), v.Kind()+233, v))
	}
	return nil
}

func Unmarshal(src io.Reader, ipv interface{}) error {
	pv := reflect.ValueOf(ipv)
	if pv.Kind() != reflect.Ptr {
		panic("unmarshalling to non-ptr")
	}
	fmt.Print("< ")
	if err := unmarshalValue(src, pv.Elem(), 0); err != nil {
		return err
	}
	fmt.Println()
	return nil
}

var rootCmd = &cobra.Command{
	Use: "f2dump",
	RunE: func(cmd *cobra.Command, args []string) error {
		var msgs fuzz2.Messages
		if err := Unmarshal(os.Stdin, &msgs); err != nil {
			fmt.Println("!!!")
			return fmt.Errorf("unmarshal msgs: %w", err)
		}
		var doc genesis.Document
		if err := Unmarshal(bytes.NewReader(msgs.InitReq.AppStateBytes), &doc); err != nil {
			fmt.Println("!!!")
			return fmt.Errorf("unmarshal doc: %w", err)
		}
		for _, msNode := range doc.Registry.Nodes {
			var n node.Node
			if err := Unmarshal(bytes.NewReader(msNode.Blob), &n); err != nil {
				fmt.Println("!!!")
				return fmt.Errorf(": %w", err)
			}
		}
		return nil
	},
}

func main() {
	_ = rootCmd.Execute()
}
