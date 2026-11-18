package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"backd/c2/mvp/tui/internal/client"
)

// parseSeen accepts the server's RFC3339 timestamps.
func parseSeen(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// SessionState returns a short liveness label for the table.
func SessionState(s client.Session, now time.Time, refresh time.Duration) string {
	t, ok := parseSeen(s.LastSeen)
	if !ok {
		return "unknown"
	}
	limit := 2 * refresh
	if limit < 15*time.Second {
		limit = 15 * time.Second
	}
	if now.Sub(t) <= limit {
		return "online"
	}
	return "stale"
}

// HumanAge renders a duration compactly (3s, 4m, 2h, 3d).
func HumanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// LastSeenAge returns "12s ago" or "?".
func LastSeenAge(s string, now time.Time) string {
	t, ok := parseSeen(s)
	if !ok {
		return "?"
	}
	return HumanAge(now.Sub(t)) + " ago"
}

// HumanBytes renders 1234567 as "1.2 MiB".
func HumanBytes(n int64) string {
	if n < 0 {
		return "?"
	}
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// StatsLine flattens server stats for the detail pane.
func StatsLine(stats map[string]any) string {
	if len(stats) == 0 {
		return "-"
	}
	b := new(strings.Builder)
	first := true
	for k, v := range stats {
		if !first {
			b.WriteString(" ")
		}
		first = false
		fmt.Fprintf(b, "%s=%v", k, v)
	}
	return b.String()
}
