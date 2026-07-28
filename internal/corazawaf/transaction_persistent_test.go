// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"
)

// recordingEngine captures the collection key each call addressed.
type recordingEngine struct {
	sets []string
	gets []string
}

func (e *recordingEngine) Close() error { return nil }
func (e *recordingEngine) Sum(_, collectionKey, _ string, _ int) error {
	e.sets = append(e.sets, collectionKey)
	return nil
}
func (e *recordingEngine) Get(_, collectionKey, _ string) (string, error) {
	e.gets = append(e.gets, collectionKey)
	return "", nil
}
func (e *recordingEngine) All(_, collectionKey string) (map[string]string, error) {
	e.gets = append(e.gets, collectionKey)
	return nil, nil
}
func (e *recordingEngine) Set(_, collectionKey, _, _ string) error {
	e.sets = append(e.sets, collectionKey)
	return nil
}
func (e *recordingEngine) SetTTL(_, collectionKey, _ string, _ int) error {
	e.sets = append(e.sets, collectionKey)
	return nil
}
func (e *recordingEngine) Remove(_, collectionKey, _ string) error {
	e.sets = append(e.sets, collectionKey)
	return nil
}

// Transactions are recycled through waf.txPool and their TransactionVariables -
// including the persistent collections - are built once per pooled struct, so
// the collection key installed by initcol has to be dropped on close. Otherwise
// the next request served by that struct addresses the previous request's
// collection instance.
func TestPersistentCollectionKeyDroppedOnClose(t *testing.T) {
	engine := &recordingEngine{}
	waf := NewWAF()
	waf.SetPersistenceEngine(engine)

	tx := waf.NewTransaction()
	tx.variables.ip.Init("1.1.1.1")
	tx.variables.session.Init("session-1")
	tx.variables.ip.SetOne("hits", "1")
	if got := engine.sets; len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("before close: writes addressed %v, want [1.1.1.1]", got)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	engine.sets = nil
	tx.variables.ip.SetOne("hits", "1")
	tx.variables.session.SetOne("suspicious", "1")
	for _, got := range engine.sets {
		if got != "" {
			t.Errorf("after close: write addressed collection key %q, want the uninitialized \"\"", got)
		}
	}
}
