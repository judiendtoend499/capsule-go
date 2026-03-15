// Copyright 2026 Quantum Pipes Technologies, LLC
// SPDX-License-Identifier: Apache-2.0

package capsule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Float-typed field paths from CPS Section 2.3.
// These must always serialize with at least one decimal place.
var floatPaths = map[string]bool{
	"reasoning.confidence":          true,
	"reasoning.options.feasibility": true,
}

// isFloatPath checks whether a JSON path corresponds to a CPS float-typed field.
// Array indices are stripped before matching, so "reasoning.options.2.feasibility"
// matches "reasoning.options.feasibility".
func isFloatPath(path string) bool {
	if floatPaths[path] {
		return true
	}
	parts := strings.Split(path, ".")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			filtered = append(filtered, p)
		}
	}
	return floatPaths[strings.Join(filtered, ".")]
}

// Canonicalize produces the CPS canonical JSON string from a capsule dict.
//
// The input map MUST have been decoded with json.Decoder.UseNumber() so that
// the integer/float distinction is preserved via json.Number values.
//
// Rules (CPS Section 2):
//   - Keys sorted lexicographically by Unicode code point, recursively
//   - Zero whitespace (no spaces after : or ,)
//   - Float-typed fields always include a decimal point
//   - Literal UTF-8 for non-ASCII characters (no \uXXXX escapes above U+007F)
//   - Array element order preserved
func Canonicalize(capsuleDict map[string]any) string {
	return canonicalValue(capsuleDict, "")
}

func canonicalValue(v any, path string) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		return escapeString(val)
	case json.Number:
		return canonicalNumber(val, path)
	case map[string]any:
		return canonicalObject(val, path)
	case []any:
		return canonicalArray(val, path)
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

func canonicalNumber(n json.Number, path string) string {
	s := n.String()
	if isFloatPath(path) && !strings.Contains(s, ".") {
		return s + ".0"
	}
	return s
}

func canonicalObject(m map[string]any, path string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(escapeString(k))
		buf.WriteByte(':')

		childPath := k
		if path != "" {
			childPath = path + "." + k
		}
		buf.WriteString(canonicalValue(m[k], childPath))
	}
	buf.WriteByte('}')
	return buf.String()
}

func canonicalArray(arr []any, path string) string {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, item := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		childPath := path + "." + strconv.Itoa(i)
		buf.WriteString(canonicalValue(item, childPath))
	}
	buf.WriteByte(']')
	return buf.String()
}

// escapeString produces a JSON string following CPS Section 2.6:
//   - Escape " and \ and control characters (U+0000 through U+001F)
//   - Do NOT escape / (solidus)
//   - Literal UTF-8 for non-ASCII (U+0080 and above)
func escapeString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r < 0x20:
			fmt.Fprintf(&buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return buf.String()
}
