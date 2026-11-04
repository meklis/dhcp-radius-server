package script

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// maxJSONDepth stops encoding of self-referencing tables.
const maxJSONDepth = 64

// jsonFuncs is the script global json. Like redis, both functions return
// nil, err on failure instead of aborting the script.
var jsonFuncs = map[string]lua.LGFunction{
	// encode(value) -> string | nil, err
	"encode": func(l *lua.LState) int {
		encoded, err := encodeJSON(l.CheckAny(1))
		if err != nil {
			return pushLuaError(l, err)
		}
		l.Push(lua.LString(encoded))
		return 1
	},
	// decode(string) -> value | nil, err
	"decode": func(l *lua.LState) int {
		var value any
		if err := json.Unmarshal([]byte(l.CheckString(1)), &value); err != nil {
			return pushLuaError(l, err)
		}
		l.Push(fromJSONValue(l, value))
		return 1
	},
}

func encodeJSON(v lua.LValue) (string, error) {
	value, err := toJSONValue(v, 0)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func toJSONValue(v lua.LValue, depth int) (any, error) {
	switch v := v.(type) {
	case *lua.LNilType:
		return nil, nil
	case lua.LBool:
		return bool(v), nil
	case lua.LNumber:
		return float64(v), nil
	case lua.LString:
		return string(v), nil
	case *lua.LTable:
		if depth >= maxJSONDepth {
			return nil, fmt.Errorf("json: table nested deeper than %d levels", maxJSONDepth)
		}
		return tableToJSONValue(v, depth)
	}
	return nil, fmt.Errorf("json: cannot encode %v", v.Type())
}

// tableToJSONValue turns a table with keys 1..n into an array and any other
// table, including an empty one, into an object.
func tableToJSONValue(t *lua.LTable, depth int) (any, error) {
	size := 0
	t.ForEach(func(_, _ lua.LValue) { size++ })

	array := make([]any, size)
	object := make(map[string]any, size)
	isArray := size > 0
	var err error
	t.ForEach(func(k, v lua.LValue) {
		if err != nil {
			return
		}
		if k.Type() != lua.LTString && k.Type() != lua.LTNumber {
			err = fmt.Errorf("json: cannot encode %v as an object key", k.Type())
			return
		}
		var value any
		if value, err = toJSONValue(v, depth+1); err != nil {
			return
		}
		object[k.String()] = value
		n, ok := k.(lua.LNumber)
		if ok && n >= 1 && int(n) <= size && lua.LNumber(int(n)) == n {
			array[int(n)-1] = value
		} else {
			isArray = false
		}
	})
	if err != nil {
		return nil, err
	}
	if isArray {
		return array, nil
	}
	return object, nil
}

func fromJSONValue(l *lua.LState, v any) lua.LValue {
	switch v := v.(type) {
	case bool:
		return lua.LBool(v)
	case float64:
		return lua.LNumber(v)
	case string:
		return lua.LString(v)
	case []any:
		t := l.NewTable()
		for i, item := range v {
			t.RawSetInt(i+1, fromJSONValue(l, item))
		}
		return t
	case map[string]any:
		t := l.NewTable()
		for key, item := range v {
			t.RawSetString(key, fromJSONValue(l, item))
		}
		return t
	}
	return lua.LNil
}
