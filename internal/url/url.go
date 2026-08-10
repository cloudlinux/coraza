// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"strings"
)

// EachQueryValue scans the URL-encoded query string in document order and
// calls f with each unescaped key/value pair. It takes separators as parameter,
// for example: & or ; or &;. Scanning stops as soon as f returns false; pairs
// past that point are never decoded.
func EachQueryValue(query string, separator byte, f func(key, value string) bool) {
	for query != "" {
		key := query
		if i := strings.IndexByte(key, separator); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.IndexByte(key, '='); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key = queryUnescape(key)
		value = queryUnescape(value)
		if !f(key, value) {
			return
		}
	}
}

// queryUnescape is a non-strict version of net/url.QueryUnescape.
func queryUnescape(input string) string {
	ilen := len(input)
	res := strings.Builder{}
	res.Grow(ilen)
	for i := 0; i < ilen; i++ {
		ci := input[i]
		if ci == '+' {
			res.WriteByte(' ')
			continue
		}
		if ci == '%' {
			if i+2 >= ilen {
				res.WriteByte(ci)
				continue
			}
			hi, ok := hexDigitToByte(input[i+1])
			if !ok {
				res.WriteByte(ci)
				continue
			}
			lo, ok := hexDigitToByte(input[i+2])
			if !ok {
				res.WriteByte(ci)
				continue
			}
			res.WriteByte(byte(hi<<4 | lo))
			i += 2
			continue
		}
		res.WriteByte(ci)
	}
	return res.String()
}

func hexDigitToByte(digit byte) (byte, bool) {
	switch {
	case digit >= '0' && digit <= '9':
		return digit - '0', true
	case digit >= 'a' && digit <= 'f':
		return digit - 'a' + 10, true
	case digit >= 'A' && digit <= 'F':
		return digit - 'A' + 10, true
	default:
		return 0, false
	}
}
