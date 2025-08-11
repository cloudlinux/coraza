// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestRedirectInit(t *testing.T) {
	t.Run("no arguments", func(t *testing.T) {
		a := redirect()
		if err := a.Init(nil, ""); err == nil || err != ErrMissingArguments {
			t.Error("expected error ErrMissingArguments")
		}
	})

	t.Run("passed arguments", func(t *testing.T) {
		a := redirect()
		if err := a.Init(nil, "abc"); err != nil {
			t.Error("unexpected error")
		}

		waf := corazawaf.NewWAF()
		tx := waf.NewTransaction()

		if want, have := "abc", a.(*redirectFn).target.Expand(tx); want != have {
			t.Errorf("unexpected target, want %q, got %q", want, have)
		}
	})

	t.Run("passed expendable arguments", func(t *testing.T) {

		waf := corazawaf.NewWAF()
		tx := waf.NewTransaction()
		tx.Variables().Env().Set("abc", []string{"xyz"})

		a := redirect()
		if err := a.Init(nil, "%{ENV.abc}"); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		if want, have := "xyz", a.(*redirectFn).target.Expand(tx); want != have {
			t.Errorf("unexpected target, want %q, got %q", want, have)
		}
	})
}
