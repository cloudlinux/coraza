// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package actions_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/persistence"
	"github.com/corazawaf/coraza/v3/experimental/persistence/ptypes"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/actions"
	noop "github.com/corazawaf/coraza/v3/internal/persistence"
)

// ttlRecorder records the key each SetTTL call addressed.
type ttlRecorder struct {
	noop.NoopEngine
	keys []string
}

func (e *ttlRecorder) SetTTL(_, _, key string, _ int) error {
	e.keys = append(e.keys, key)
	return nil
}

// setvar stores under a lowercased key, and the rule parser lowercases selectors
// on the persistent collections, so expirevar has to agree. Otherwise
// `setvar:ip.Blocked=1` plus `expirevar:ip.Blocked=60` sets the TTL on a key
// nothing else ever touches and the value never expires.
func TestExpirevarLowercasesKey(t *testing.T) {
	a, err := actions.Get("expirevar")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Init(&md{}, "IP.Blocked=60"); err != nil {
		t.Fatal(err)
	}

	engine := &ttlRecorder{}
	config, err := persistence.SetEngine(
		coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"),
		func() (ptypes.PersistentEngine, error) { return engine, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	waf, err := coraza.NewWAF(config)
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})

	a.Evaluate(&md{}, tx.(plugintypes.TransactionState))

	if len(engine.keys) != 1 || engine.keys[0] != "blocked" {
		t.Errorf("SetTTL addressed %q, want [blocked]", engine.keys)
	}
}
