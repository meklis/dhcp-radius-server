package clientdb

import (
	"slices"
	"strconv"
	"sync"
)

// bindIndex holds one named bind source indexed for every FindBinds lookup.
// Several binds may share a key (e.g. a client behind different ports).
// mu guards live updates applied to an already published index.
type bindIndex struct {
	mu              sync.RWMutex
	byID            map[string]*Bind
	byMac           map[string][]*Bind
	byMacDevice     map[string][]*Bind
	byMacDevicePort map[string][]*Bind
	byDevicePort    map[string][]*Bind
}

func newBindIndex() *bindIndex {
	return &bindIndex{
		byID:            make(map[string]*Bind),
		byMac:           make(map[string][]*Bind),
		byMacDevice:     make(map[string][]*Bind),
		byMacDevicePort: make(map[string][]*Bind),
		byDevicePort:    make(map[string][]*Bind),
	}
}

// eachKey calls fn for every secondary index the bind belongs to.
func (idx *bindIndex) eachKey(b *Bind, fn func(index map[string][]*Bind, key string)) {
	fn(idx.byMac, b.ClientMac)
	if b.DeviceMac == "" {
		return
	}
	fn(idx.byMacDevice, b.ClientMac+"|"+b.DeviceMac)
	if b.Port == 0 {
		return
	}
	port := strconv.Itoa(b.Port)
	fn(idx.byMacDevicePort, b.ClientMac+"|"+b.DeviceMac+"|"+port)
	fn(idx.byDevicePort, b.DeviceMac+"|"+port)
}

// put inserts or replaces a bind by ID without locking; the caller must hold
// mu or own an index that is not published yet. Reports whether the ID existed.
func (idx *bindIndex) put(b *Bind) bool {
	existed := idx.remove(b.ID)
	idx.byID[b.ID] = b
	idx.eachKey(b, func(index map[string][]*Bind, key string) {
		index[key] = append(index[key], b)
	})
	return existed
}

// remove deletes a bind by ID without locking, see put.
func (idx *bindIndex) remove(id string) bool {
	old, ok := idx.byID[id]
	if !ok {
		return false
	}
	delete(idx.byID, id)
	idx.eachKey(old, func(index map[string][]*Bind, key string) {
		if rest := slices.DeleteFunc(index[key], func(b *Bind) bool { return b.ID == id }); len(rest) > 0 {
			index[key] = rest
		} else {
			delete(index, key)
		}
	})
	return true
}

func (idx *bindIndex) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.byID)
}
