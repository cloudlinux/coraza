// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package actions_test

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/experimental/persistence"
	"github.com/corazawaf/coraza/v3/experimental/persistence/ptypes"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/actions"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type md struct {
}

func (md) ID() int {
	return 0
}
func (md) ParentID() int {
	return 0
}
func (md) Status() int {
	return 0
}

func TestPersistenceSetvar(t *testing.T) {
	a, err := actions.Get("setvar")
	if err != nil {
		t.Error("failed to get setvar action")
	}

	corazaConfig := coraza.NewWAFConfig().WithDirectives("SecRuleEngine On")
	corazaConfig, err = persistence.SetEngine(corazaConfig, newDefaultEngine)
	if err != nil {
		t.Fatal(err)
	}
	waf, err := coraza.NewWAF(corazaConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("SESSION should be set", func(t *testing.T) {
		if err := a.Init(&md{}, "SESSION.test=test"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		tx := waf.NewTransaction()
		txs := tx.(plugintypes.TransactionState)
		a.Evaluate(&md{}, txs)
		col := txs.Collection(variables.Session)
		col.FindAll()
		err = persistence.ClosePersistentEngine(waf)
		if err != nil {
			t.Fatal(err)
		}
	})
}

type defaultEngine struct {
	data   sync.Map
	ttl    int
	stopGC chan bool
}

func newDefaultEngine() (ptypes.PersistentEngine, error) {
	d := &defaultEngine{sync.Map{}, int(time.Now().Add(10 * time.Minute).Unix()), make(chan bool)}
	go d.gc()
	return d, nil
}

func (d *defaultEngine) Close() error {
	// Close will just stop the GC
	// it won't delete the data as it would cause race conditions.
	d.stopGC <- true
	return nil
}

func (d *defaultEngine) Sum(collectionName string, collectionKey string, key string, sum int) error {
	col := d.getCollection(collectionName, collectionKey)
	if col == nil {
		d.set(collectionName, collectionKey, key, sum)
	} else {
		if v, ok := col[key]; ok {
			if v2, ok := v.(int); ok {
				d.set(collectionName, collectionKey, key, v2+sum)
			}
		} else {
			d.set(collectionName, collectionKey, key, sum)
		}
	}
	return nil
}

func (d *defaultEngine) Get(collectionName string, collectionKey string, key string) (string, error) {
	res := d.get(collectionName, collectionKey, key)
	switch v := res.(type) {
	case string:
		return v, nil
	case int:
		return strconv.Itoa(v), nil
	case nil:
		return "", nil
	}

	return "", nil
}

func (d *defaultEngine) Set(collection string, collectionKey string, key string, value string) error {
	d.set(collection, collectionKey, key, value)
	return nil
}

func (d *defaultEngine) Remove(collection string, collectionKey string, key string) error {
	data := d.getCollection(collection, collectionKey)
	if data == nil {
		return nil
	}
	delete(data, key)
	return nil
}

func (d *defaultEngine) All(collectionName string, collectionKey string) (map[string]string, error) {
	data := d.getCollection(collectionName, collectionKey)
	if data == nil {
		return nil, nil
	}
	res := map[string]string{}
	for k, v := range data {
		if v == nil {
			res[k] = ""
		} else {
			switch v2 := v.(type) {
			case string:
				res[k] = v2
			case int:
				res[k] = strconv.Itoa(v2)
			}
		}
	}
	return res, nil
}

func (d *defaultEngine) SetTTL(collection string, collectionKey string, key string, ttl int) error {
	data := d.getCollection(collection, collectionKey)
	if data == nil {
		return nil
	}
	v, ok := data["TTL_SET"]
	if ok {
		setTTL, ok := v.(bool)
		if ok && setTTL {
			return nil
		}
	}

	data["TIMEOUT"] = int(time.Now().Unix()) + ttl
	data["TTL_SET"] = true
	return nil
}

func (d *defaultEngine) gc() {
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-d.stopGC:
			ticker.Stop()
			return
		case <-ticker.C:
			d.data.Range(func(key, value interface{}) bool {
				col := value.(map[string]interface{})
				timeout, ok := col["TIMEOUT"].(int)
				if !ok {
					return true
				}
				if timeout < int(time.Now().Unix()) {
					d.data.Delete(key)
				}
				return true
			})
		}
	}
}

func (d *defaultEngine) getCollection(collectionName string, collectionKey string) map[string]interface{} {
	k := d.getCollectionName(collectionName, collectionKey)
	data, ok := d.data.Load(k)
	if !ok {
		return nil
	}
	return data.(map[string]interface{})
}

func (d *defaultEngine) get(collectionName string, collectionKey string, key string) interface{} {
	data := d.getCollection(collectionName, collectionKey)
	if data == nil {
		return nil
	}
	if res, ok := data[key]; ok {
		return res
	}
	return nil
}

func (d *defaultEngine) set(collection string, collectionKey string, key string, value interface{}) {
	data := d.getCollection(collection, collectionKey)
	now := int(time.Now().Unix())
	if data == nil {
		data := map[string]interface{}{
			key:                value,
			"CREATE_TIME":      now,
			"IS_NEW":           1,
			"KEY":              collectionKey,
			"LAST_UPDATE_TIME": 0,
			"TIMEOUT":          now + d.ttl,
			"UPDATE_COUNTER":   0,
			"UPDATE_RATE":      0,
		}
		d.data.Store(d.getCollectionName(collection, collectionKey), data)
	} else {
		data[key] = value
		d.updateCollection(data)
	}
}

func (*defaultEngine) getCollectionName(collectionName string, collectionKey string) string {
	return fmt.Sprintf("%s_%s", collectionName, collectionKey)
}

func (d *defaultEngine) updateCollection(col map[string]interface{}) {
	update_counter := col["UPDATE_COUNTER"].(int)
	time_now := int(time.Now().Unix())
	col["IS_NEW"] = 0
	col["LAST_UPDATE_TIME"] = time_now
	col["UPDATE_COUNTER"] = update_counter + 1
	// we compute the update rate by using UPDATE_COUNTER and CREATE_TIME
	// UPDATE_RATE = UPDATE_COUNTER / (CURRENT_TIME - CREATE_TIME)
	delta := (time_now - col["CREATE_TIME"].(int))
	if delta > 0 {
		col["UPDATE_RATE"] = int(update_counter / delta)
	}
}
