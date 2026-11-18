package operator

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ParseKV parses "--key value", "--key=value" and bare "--flag" arguments
// into a JSON-ready map. Values that look like ints/bools are typed.
func ParseKV(args []string) (map[string]any, error) {
	out := map[string]any{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return nil, fmt.Errorf("unexpected argument %q", a)
		}
		a = strings.TrimPrefix(a, "--")
		if a == "" {
			continue
		}
		var key, val string
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			key, val = a[:eq], a[eq+1:]
		} else {
			key = a
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				val = args[i+1]
				i++
			} else {
				out[key] = true
				continue
			}
		}
		switch strings.ToLower(val) {
		case "true":
			out[key] = true
		case "false":
			out[key] = false
		default:
			if n, err := strconv.Atoi(val); err == nil {
				out[key] = n
			} else {
				out[key] = val
			}
		}
	}
	if v, ok := out["args"].(string); ok {
		if !json.Valid([]byte(v)) {
			return nil, fmt.Errorf("--args is not valid JSON")
		}
		out["args"] = json.RawMessage(v)
	}
	return out, nil
}
