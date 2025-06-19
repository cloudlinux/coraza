// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package persistence

import "testing"

func TestNoopEngine(t *testing.T) {
	ne := NoopEngine{}

	_ = ne.Close()
	_ = ne.Sum("test", "test", "test", 0)
	_, _ = ne.Get("test", "test", "test")
	_ = ne.Set("test", "test", "test", "test")
	_ = ne.Remove("test", "test", "test")
	_ = ne.SetTTL("test", "test", "test", 0)
	_, _ = ne.All("test", "test")
}
