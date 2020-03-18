package fill2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"time"
)

type Pour interface {
	Pour(dst io.Writer)
}

func marshalValue(dst io.Writer, v reflect.Value, indent int) {
	if !v.CanInterface() {
		fmt.Print("(unexported)")
		return
	}
	if pour, ok := v.Addr().Interface().(Pour); ok {
		fmt.Printf("(pour '%s %v)", v.Type().Name(), pour)
		pour.Pour(dst)
		return
	}
	switch v.Type() {
	case reflect.TypeOf(time.Time{}):
		t := v.Interface().(time.Time)
		fmt.Printf("(time \"%v\")", t)
		sec := t.Unix()
		if err := binary.Write(dst, binary.LittleEndian, sec); err != nil {
			panic(err)
		}
		if err := binary.Write(dst, binary.LittleEndian, uint32(t.Nanosecond())); err != nil {
			panic(err)
		}
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		fmt.Printf("(bool %v)", v.Bool())
		if err := binary.Write(dst, binary.LittleEndian, v.Bool()); err != nil {
			panic(err)
		}
	case reflect.Int:
		fmt.Printf("(int %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, v.Int()); err != nil {
			panic(err)
		}
	case reflect.Int8:
		fmt.Printf("(int8 %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, int8(v.Int())); err != nil {
			panic(err)
		}
	case reflect.Int16:
		fmt.Printf("(int16 %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, int16(v.Int())); err != nil {
			panic(err)
		}
	case reflect.Int32:
		fmt.Printf("(int32 %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, int32(v.Int())); err != nil {
			panic(err)
		}
	case reflect.Int64:
		fmt.Printf("(int64 %d)", v.Int())
		if err := binary.Write(dst, binary.LittleEndian, v.Int()); err != nil {
			panic(err)
		}
	case reflect.Uint:
		fmt.Printf("(uint %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, v.Uint()); err != nil {
			panic(err)
		}
	case reflect.Uint8:
		fmt.Printf("(uint8 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, uint8(v.Uint())); err != nil {
			panic(err)
		}
	case reflect.Uint16:
		fmt.Printf("(uint16 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, uint16(v.Uint())); err != nil {
			panic(err)
		}
	case reflect.Uint32:
		fmt.Printf("(uint32 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, uint32(v.Uint())); err != nil {
			panic(err)
		}
	case reflect.Uint64:
		fmt.Printf("(uint64 %d)", v.Uint())
		if err := binary.Write(dst, binary.LittleEndian, v.Uint()); err != nil {
			panic(err)
		}
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			asBytes := v.Slice(0, v.Len()).Bytes()
			fmt.Printf("(bytearray \"%x\")", asBytes)
			if _, err := dst.Write(asBytes); err != nil {
				panic(err)
			}
			return
		}
		fmt.Printf("(array\n%s", strings.Repeat("\t", indent))
		for i := 0; i < v.Len(); i++ {
			fmt.Print("\t(item ")
			marshalValue(dst, v.Index(i), indent+1)
			fmt.Printf(")\n%s", strings.Repeat("\t", indent))
		}
		fmt.Print(")")
	case reflect.Map:
		if v.IsNil() {
			fmt.Print("(map nil)")
			if err := binary.Write(dst, binary.LittleEndian, false); err != nil {
				panic(err)
			}
		} else {
			fmt.Printf("(map\n%s", strings.Repeat("\t", indent))
			if err := binary.Write(dst, binary.LittleEndian, true); err != nil {
				panic(err)
			}
			if v.Len() > math.MaxUint8 {
				panic(fmt.Sprintf("map len %d too long (max %d)", v.Len(), math.MaxInt8))
			}
			if err := binary.Write(dst, binary.LittleEndian, uint8(v.Len())); err != nil {
				panic(err)
			}
			mr := v.MapRange()
			for mr.Next() {
				fmt.Print("\t(item ")
				// Obtain addressable copies of the key and value.
				kk := reflect.New(v.Type().Key())
				kk.Elem().Set(mr.Key())
				marshalValue(dst, kk.Elem(), indent+1)
				fmt.Print(" ")
				vv := reflect.New(v.Type().Elem())
				vv.Elem().Set(mr.Value())
				marshalValue(dst, vv.Elem(), indent+1)
				fmt.Printf(")\n%s", strings.Repeat("\t", indent))
			}
			fmt.Print(")")
		}
	case reflect.Ptr:
		if v.IsNil() {
			fmt.Print("(ptr nil)")
			if err := binary.Write(dst, binary.LittleEndian, false); err != nil {
				panic(err)
			}
		} else {
			fmt.Print("(ptr ")
			if err := binary.Write(dst, binary.LittleEndian, true); err != nil {
				panic(err)
			}
			marshalValue(dst, v.Elem(), indent)
			fmt.Print(")")
		}
	case reflect.Slice:
		if v.IsNil() {
			fmt.Print("(slice nil)")
			if err := binary.Write(dst, binary.LittleEndian, false); err != nil {
				panic(err)
			}
		} else {
			if err := binary.Write(dst, binary.LittleEndian, true); err != nil {
				panic(err)
			}
			if v.Type().Elem().Kind() == reflect.Uint8 {
				asBytes := v.Bytes()
				fmt.Printf("(byteslice \"%x\")", asBytes)
				if v.Len() > math.MaxUint16 {
					panic(fmt.Sprintf("byte slice len %d too long (max %d)", v.Len(), math.MaxUint16))
				}
				if err := binary.Write(dst, binary.LittleEndian, uint16(v.Len())); err != nil {
					panic(err)
				}
				if _, err := dst.Write(asBytes); err != nil {
					panic(err)
				}
				return
			}
			fmt.Printf("(slice\n%s", strings.Repeat("\t", indent))
			if v.Len() > math.MaxUint8 {
				panic(fmt.Sprintf("slice len %d too long (max %d)", v.Len(), math.MaxUint8))
			}
			if err := binary.Write(dst, binary.LittleEndian, uint8(v.Len())); err != nil {
				panic(err)
			}
			for i := 0; i < v.Len(); i++ {
				fmt.Print("\t(item ")
				marshalValue(dst, v.Index(i), indent+1)
				fmt.Printf(")\n%s", strings.Repeat("\t", indent))
			}
			fmt.Print(")")
		}
	case reflect.String:
		fmt.Printf("(string %+q)", v.String())
		if v.Len() > math.MaxUint8 {
			panic(fmt.Sprintf("string len %d too long (max %d)", v.Len(), math.MaxUint8))
		}
		asBytes := []byte(v.String())
		if err := binary.Write(dst, binary.LittleEndian, uint8(len(asBytes))); err != nil {
			panic(err)
		}
		if _, err := dst.Write(asBytes); err != nil {
			panic(err)
		}
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
			marshalValue(dst, v.Field(i), indent+1)
			fmt.Printf(")\n%s", strings.Repeat("\t", indent))
		}
		fmt.Print(")")
	default:
		panic(fmt.Sprintf("not supported kind %d (line %d) %#v", v.Kind(), v.Kind()+233, v))
	}
}

func Marshal(ipv interface{}) []byte {
	var buf bytes.Buffer
	pv := reflect.ValueOf(ipv)
	if pv.Kind() != reflect.Ptr {
		panic("marshalling from non-ptr")
	}
	fmt.Print("> ")
	marshalValue(&buf, pv.Elem(), 0)
	fmt.Println()
	return buf.Bytes()
}

type Fill interface {
	Fill(src io.Reader) error
}

func unmarshalValue(src io.Reader, v reflect.Value, indent int) error {
	if !v.CanSet() {
		fmt.Print("(unexported)")
		return nil
	}
	if fill, ok := v.Addr().Interface().(Fill); ok {
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
			if _, err := io.ReadFull(src, asBytes); err != nil {
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
				if _, err := io.ReadFull(src, b); err != nil {
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
		if _, err := io.ReadFull(src, b); err != nil {
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

func Unmarshal(data []byte, ipv interface{}) error {
	pv := reflect.ValueOf(ipv)
	if pv.Kind() != reflect.Ptr {
		panic("unmarshalling to non-ptr")
	}
	fmt.Print("< ")
	if err := unmarshalValue(bytes.NewReader(data), pv.Elem(), 0); err != nil {
		return err
	}
	fmt.Println()
	return nil
}

func MustUnmarshal(data []byte, ipv interface{}) {
	if err := Unmarshal(data, ipv); err != nil {
		panic(err)
	}
}
