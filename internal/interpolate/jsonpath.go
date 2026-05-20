package interpolate

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// extractJSON walks a decoded JSON value using a simple dot-bracket path.
//
// Path syntax:
//
//	field          → root["field"]
//	a.b.c          → root["a"]["b"]["c"]
//	items[0].id    → root["items"][0]["id"]
//
// Only object field access and array index access are supported.
// Returns an error when the path cannot be resolved against the value.
func extractJSON(data []byte, path string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("interpolate: empty JSON body")
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return "", fmt.Errorf("interpolate: body is not valid JSON: %w", err)
	}
	val, err := walkPath(root, path)
	if err != nil {
		return "", err
	}
	return stringify(val), nil
}

// walkPath resolves path segments against v step by step.
func walkPath(v any, path string) (any, error) {
	if path == "" {
		return v, nil
	}
	segments := splitPath(path)
	for _, seg := range segments {
		switch node := v.(type) {
		case map[string]any:
			child, ok := node[seg.key]
			if !ok {
				return nil, fmt.Errorf("interpolate: json path: field %q not found", seg.key)
			}
			v = child
		case []any:
			if seg.index < 0 || seg.index >= len(node) {
				return nil, fmt.Errorf("interpolate: json path: index [%d] out of range (length %d)", seg.index, len(node))
			}
			v = node[seg.index]
		default:
			return nil, fmt.Errorf("interpolate: json path: cannot traverse into %T", v)
		}
	}
	return v, nil
}

// pathSegment represents one step in a path (either a key or an array index).
type pathSegment struct {
	key     string
	index   int // only valid when isIndex == true
	isIndex bool
}

// splitPath splits a dot-bracket path into segments.
// "a.b[0].c" → [{key:"a"}, {key:"b"}, {index:0}, {key:"c"}]
func splitPath(path string) []pathSegment {
	var segments []pathSegment
	// Split on dots first, then handle bracket accesses within each part.
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		// Split bracket index accesses within this part.
		for {
			start := strings.Index(part, "[")
			if start < 0 {
				if part != "" {
					segments = append(segments, pathSegment{key: part})
				}
				break
			}
			if start > 0 {
				segments = append(segments, pathSegment{key: part[:start]})
			}
			end := strings.Index(part[start:], "]")
			if end < 0 {
				// malformed — treat rest as a key
				segments = append(segments, pathSegment{key: part[start:]})
				part = ""
				break
			}
			idxStr := part[start+1 : start+end]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				// treat bracketed text as a field key
				segments = append(segments, pathSegment{key: part[start : start+end+1]})
			} else {
				segments = append(segments, pathSegment{index: idx, isIndex: true})
			}
			part = part[start+end+1:]
		}
	}
	return segments
}

// stringify converts any JSON value to its string representation.
// Objects and arrays are re-encoded as compact JSON; scalars are formatted naturally.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// Use integer notation when the value is whole.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case string:
		return t
	default:
		// Object or array: re-encode as compact JSON.
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}
