package script

import (
	"errors"
	"time"

	"github.com/meklis/dhcp-radius-server/redisconn"
	redis "github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// redisTable builds the script global redis: one object per configured server,
// addressed by its config key (redis.main:set(...)). Methods follow the Lua
// convention of returning nil, err on failure, so a Redis outage is up to the
// script to handle rather than aborting it.
func redisTable(ls *lua.LState, clients redisconn.Clients) *lua.LTable {
	t := ls.NewTable()
	for key, client := range clients {
		t.RawSetString(key, ls.SetFuncs(ls.NewTable(), redisFuncs(client)))
	}
	return t
}

func redisFuncs(client *redis.Client) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		// set(key, value, [ttl_sec]) -> true | nil, err; see redisValue
		"set": func(l *lua.LState) int {
			ttl := time.Duration(l.OptInt64(4, 0)) * time.Second
			value, err := redisValue(l, 3)
			if err != nil {
				return pushLuaError(l, err)
			}
			if err := client.Set(luaContext(l), l.CheckString(2), value, ttl).Err(); err != nil {
				return pushLuaError(l, err)
			}
			l.Push(lua.LTrue)
			return 1
		},
		// get(key) -> value | nil (no such key) | nil, err
		"get": func(l *lua.LState) int {
			value, err := client.Get(luaContext(l), l.CheckString(2)).Result()
			if errors.Is(err, redis.Nil) {
				l.Push(lua.LNil)
				return 1
			}
			if err != nil {
				return pushLuaError(l, err)
			}
			l.Push(lua.LString(value))
			return 1
		},
		// incr(key, [by]) -> new value | nil, err
		"incr": func(l *lua.LState) int {
			value, err := client.IncrBy(luaContext(l), l.CheckString(2), l.OptInt64(3, 1)).Result()
			return pushRedisInt(l, value, err)
		},
		// del(key) -> number of deleted keys | nil, err
		"del": func(l *lua.LState) int {
			value, err := client.Del(luaContext(l), l.CheckString(2)).Result()
			return pushRedisInt(l, value, err)
		},
		// publish(channel, message) -> number of receivers | nil, err; see redisValue
		"publish": func(l *lua.LState) int {
			message, err := redisValue(l, 3)
			if err != nil {
				return pushLuaError(l, err)
			}
			value, err := client.Publish(luaContext(l), l.CheckString(2), message).Result()
			return pushRedisInt(l, value, err)
		},
	}
}

// redisValue sends strings unchanged and encodes anything else as JSON, so
// numbers and booleans stay plain and tables become objects or arrays.
func redisValue(l *lua.LState, idx int) (string, error) {
	v := l.Get(idx)
	if v == lua.LNil {
		l.ArgError(idx, "value expected")
	}
	if s, ok := v.(lua.LString); ok {
		return string(s), nil
	}
	return encodeJSON(v)
}

func pushRedisInt(l *lua.LState, value int64, err error) int {
	if err != nil {
		return pushLuaError(l, err)
	}
	l.Push(lua.LNumber(value))
	return 1
}
